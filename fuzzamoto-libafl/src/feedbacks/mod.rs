use regex::bytes::Regex;
use std::{borrow::Cow, cell::RefCell, fmt::Debug, rc::Rc};

use core::marker::PhantomData;
use libafl::{
    HasMetadata,
    corpus::Testcase,
    events::{Event, EventFirer, EventWithStats},
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    inputs::Input,
    monitors::stats::{AggregatorOps, UserStats, UserStatsValue},
    observers::{ObserversTuple, StdOutObserver},
    state::{HasCorpus, HasExecutions},
};
use libafl_bolts::{
    Error, Named,
    tuples::{Handle, MatchNameRef},
};
use std::path::{Path, PathBuf};
use strum::Display;

use crate::{input::IrInput, stages::TimeoutsToVerify};

/// A Feedback that captures all timeouts and stores them in State for re-evaluation later.
/// Use in conjunction with `VerifyTimeoutsStage`
#[derive(Debug)]
pub struct CaptureTimeoutFeedback {
    enabled: Rc<RefCell<bool>>,
    timeout_found: usize,
    objective_dir: PathBuf,
    triggered: bool,
}

impl CaptureTimeoutFeedback {
    /// Create a new [`CaptureTimeoutFeedback`].
    pub fn new(enabled: Rc<RefCell<bool>>, objective_dir: &Path) -> Self {
        Self {
            enabled,
            timeout_found: 0,
            objective_dir: objective_dir.to_path_buf(),
            triggered: false,
        }
    }

    fn set_filename(&self, prefix: &str, testcase: &mut Testcase<IrInput>) {
        let base = if let Some(filename) = testcase.filename() {
            filename.clone()
        } else {
            testcase.input().as_ref().unwrap().generate_name(None)
        };
        let file_path = self.objective_dir.join(format!("{prefix}-{base}",));
        *testcase.file_path_mut() = Some(file_path);
    }
}

impl Named for CaptureTimeoutFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CaptureTimeoutFeedback");
        &NAME
    }
}

impl<S> StateInitializer<S> for CaptureTimeoutFeedback {}

impl<EM, OT, S> Feedback<EM, IrInput, OT, S> for CaptureTimeoutFeedback
where
    S: HasCorpus<IrInput> + HasMetadata + HasExecutions,
    EM: EventFirer<IrInput, S>,
{
    #[inline]
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        input: &IrInput,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        self.triggered = false;

        if *self.enabled.borrow() && matches!(exit_kind, ExitKind::Timeout) {
            let timeouts = state.metadata_or_insert_with(TimeoutsToVerify::new);
            log::info!("Timeout detected, adding to verification queue!");
            // If we're using incremental snapshots, clear frozen_prefix_len.
            let mut timeout_input = input.clone();
            timeout_input.frozen_prefix_len = None;
            timeouts.push(timeout_input);
            return Ok(false);
        }

        self.triggered = matches!(exit_kind, ExitKind::Timeout);

        Ok(matches!(exit_kind, ExitKind::Timeout))
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<IrInput>,
    ) -> Result<(), Error> {
        if self.triggered {
            self.timeout_found += 1;
            manager.fire(
                state,
                EventWithStats::with_current_time(
                    Event::UpdateUserStats {
                        name: Cow::from("timeout"),
                        value: UserStats::new(
                            UserStatsValue::Number(self.timeout_found as u64),
                            AggregatorOps::Sum,
                        ),
                        phantom: PhantomData,
                    },
                    *state.executions(),
                ),
            )?;

            self.set_filename("timeout", testcase);
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct CrashCauseStats {
    map: std::collections::HashMap<CrashCause, usize>,
}

#[derive(Eq, Hash, PartialEq, Display, Debug)]
enum CrashCause {
    CRASH,
    BLOCKTEMPLATE,
    INFLATION,
    NETSPLIT,
    CONSENSUS,
    OTHER,
}

pub struct CrashCauseFeedback {
    handle: Handle<StdOutObserver>,
    stats: CrashCauseStats,
    objective_dir: PathBuf,
}

impl CrashCauseFeedback {
    pub fn new(handle: Handle<StdOutObserver>, objective_dir: &Path) -> Self {
        Self {
            handle,
            stats: CrashCauseStats::default(),
            objective_dir: objective_dir.to_path_buf(),
        }
    }

    fn set_filename(&self, prefix: &str, testcase: &mut Testcase<IrInput>) {
        let base = if let Some(filename) = testcase.filename() {
            filename.clone()
        } else {
            testcase.input().as_ref().unwrap().generate_name(None)
        };
        let file_path = self.objective_dir.join(format!("{prefix}-{base}",));
        *testcase.file_path_mut() = Some(file_path);
    }
}

impl Named for CrashCauseFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CrashCauseFeedback");
        &NAME
    }
}

impl<S> StateInitializer<S> for CrashCauseFeedback {}

impl<EM, OT, S> Feedback<EM, IrInput, OT, S> for CrashCauseFeedback
where
    OT: ObserversTuple<IrInput, S>,
    S: HasCorpus<IrInput> + HasMetadata + HasExecutions,
    EM: EventFirer<IrInput, S>,
{
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &IrInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<IrInput>,
    ) -> Result<(), Error> {
        let mut cause = None;
        let re = Regex::new(r"CRASH: ([^\n;]+)")
            .map_err(|_| libafl::Error::illegal_state("Failed to construct regex"))?;

        let stdout_observer = observers
            .get(&self.handle)
            .ok_or_else(|| Error::illegal_state("StdOutObserver is missing"))?;
        let mut found = false;
        if let Some(x) = &stdout_observer.output
            && let Some(caps) = re.captures(x)
            && let Some(matched) = caps.get(1)
        {
            found = true;
            match matched.as_bytes() {
                b"CRASH" => {
                    self.stats
                        .map
                        .entry(CrashCause::CRASH)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::CRASH);
                }
                b"INFLATION" => {
                    self.stats
                        .map
                        .entry(CrashCause::INFLATION)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::INFLATION);
                }
                b"BLOCKTEMPLATE" => {
                    self.stats
                        .map
                        .entry(CrashCause::BLOCKTEMPLATE)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::BLOCKTEMPLATE);
                }
                b"NETSPLIT" => {
                    self.stats
                        .map
                        .entry(CrashCause::NETSPLIT)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::NETSPLIT);
                }
                b"CONSENSUS" => {
                    self.stats
                        .map
                        .entry(CrashCause::CONSENSUS)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::CONSENSUS);
                }
                _ => {
                    self.stats
                        .map
                        .entry(CrashCause::OTHER)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    cause = Some(CrashCause::OTHER);
                }
            }
        }

        if found {
            for (cause, value) in &self.stats.map {
                if *value > 0 {
                    let name: String = cause.to_string();
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::UpdateUserStats {
                                name: Cow::from(name),
                                value: UserStats::new(
                                    UserStatsValue::Number(*value as u64),
                                    AggregatorOps::Sum,
                                ),
                                phantom: PhantomData,
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
        }

        match cause {
            Some(CrashCause::CRASH) => {
                self.set_filename("crash", testcase);
            }
            Some(CrashCause::BLOCKTEMPLATE) => {
                self.set_filename("blocktemplate", testcase);
            }
            Some(CrashCause::INFLATION) => {
                self.set_filename("inflation", testcase);
            }
            Some(CrashCause::NETSPLIT) => {
                self.set_filename("netsplit", testcase);
            }
            Some(CrashCause::CONSENSUS) => {
                self.set_filename("consensus", testcase);
            }
            Some(CrashCause::OTHER) => {
                self.set_filename("other", testcase);
            }
            _ => {
                // do nothing
            }
        }

        Ok(())
    }
}
