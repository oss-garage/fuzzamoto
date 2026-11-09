use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use libafl::HasMetadata;
use libafl::corpus::Testcase;
use libafl::observers::StdOutObserver;
use libafl_bolts::tuples::{Handle, Handled, MatchName, MatchNameRef};
use libafl_bolts::{Error, Named, impl_serdeany};

use libafl::{
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
};

use fuzzamoto::assertions::{AssertionScope, write_assertions};

/// Parse assertions from raw stdout bytes.
///
/// This extracts all `AssertionScope` entries from the stdout output of a
/// fuzzamoto target execution.
pub fn parse_assertions_from_stdout(buffer: &[u8]) -> HashMap<String, AssertionScope> {
    let stdout = String::from_utf8_lossy(buffer);
    let mut assertions = HashMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim().trim_matches(|c| c == '\0');
        if let Ok(fuzzamoto::StdoutMessage::Assertion(data)) =
            serde_json::from_str::<fuzzamoto::StdoutMessage>(trimmed)
        {
            use base64::prelude::{BASE64_STANDARD, Engine};
            if let Ok(decoded) = BASE64_STANDARD.decode(&data)
                && let Ok(json) = String::from_utf8(decoded)
                && let Ok(assertion) = serde_json::from_str::<AssertionScope>(&json)
            {
                assertions.insert(assertion.message(), assertion);
            }
        }
    }
    assertions
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AssertionFeedback {
    assertions: HashMap<String, AssertionScope>,
    o_ref: Handle<StdOutObserver>,

    last_assertion_updates: Vec<String>,

    #[serde(skip)]
    last_update: Option<Instant>,
    #[serde(skip)]
    update_interval: Option<Duration>,
    #[serde(skip)]
    output_file: Option<PathBuf>,

    // Only consider always assertions
    only_always_assertions: bool,
    enabled: bool,
}

impl AssertionFeedback {
    fn evaluate_assertion(&mut self, new: AssertionScope) -> bool {
        if self.only_always_assertions && matches!(new, AssertionScope::Sometimes(_, _)) {
            return false;
        }

        let previous = self.assertions.get(&new.message());

        let result = match (previous, &new) {
            // Track new sometimes assertions even when they are not satisfied yet.
            // Once tracked, future executions can become interesting by reducing
            // the distance to the asserted condition.
            (None, new) => new.evaluate() || !self.only_always_assertions,
            (Some(prev), new) => {
                (!prev.evaluate() && new.evaluate()) || (prev.distance() > new.distance())
            }
        };

        if result {
            log::debug!("{previous:?} -> {new:?}");
            self.last_assertion_updates.push(new.message());
            self.assertions.insert(new.message(), new);
        }

        result
    }
}

impl<S> StateInitializer<S> for AssertionFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for AssertionFeedback
where
    OT: MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        self.last_assertion_updates.clear();

        if !self.enabled {
            return Ok(false);
        }

        let observer = observers
            .get(&self.o_ref)
            .ok_or(Error::illegal_state("StdOutObserver is missing"))?;
        let buffer = observer
            .output
            .as_ref()
            .ok_or(Error::illegal_state("StdOutObserver has no stdout"))?;

        let parsed = parse_assertions_from_stdout(buffer);
        let mut interesting = false;
        for (_, assertion) in parsed {
            interesting |= self.evaluate_assertion(assertion);
        }

        let now = Instant::now();
        if !self.only_always_assertions
            && let Some(output_path) = self.output_file.as_ref()
            && now > self.last_update.unwrap() + self.update_interval.unwrap()
        {
            self.last_update = Some(now);

            let mut output_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(output_path)
                .map_err(|e| {
                    log::warn!("Writing assertions to file: {e:?}");
                    libafl::Error::unknown(format!("Failed to open output file: {e}"))
                })?;
            write_assertions(&mut output_file, &self.assertions).map_err(|e| {
                libafl::Error::unknown(format!("Failed to write to output file: {e}"))
            })?;
        }

        Ok(interesting)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        let mut assertions = HashMap::new();
        for msg in &self.last_assertion_updates {
            if let Some(assertion) = self.assertions.get(msg) {
                assertions.insert(msg.clone(), assertion.clone());
            }
        }

        testcase.add_metadata(AssertionMetadata { assertions });

        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AssertionMetadata {
    pub assertions: HashMap<String, AssertionScope>,
}

impl_serdeany!(AssertionMetadata);

impl Named for AssertionFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.o_ref.name()
    }
}

impl AssertionFeedback {
    /// Creates a new [`AssertionFeedback`].
    #[must_use]
    pub fn new(observer: &StdOutObserver, output_file: PathBuf, enabled: bool) -> Self {
        let interval = Duration::from_secs(30);
        Self {
            o_ref: observer.handle(),
            assertions: HashMap::new(),
            last_assertion_updates: Vec::new(),
            output_file: Some(output_file),

            last_update: Some(Instant::now().checked_sub(interval * 2).unwrap()),
            update_interval: Some(interval),

            only_always_assertions: false,
            enabled,
        }
    }
    pub fn new_only_always(observer: &StdOutObserver, enabled: bool) -> Self {
        Self {
            o_ref: observer.handle(),
            assertions: HashMap::new(),
            last_assertion_updates: Vec::new(),
            output_file: None,
            last_update: None,
            update_interval: None,
            only_always_assertions: true,
            enabled,
        }
    }
}
