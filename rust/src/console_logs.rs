use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::sync::broadcast;
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::layer::{Context, Layer};

const MAX_LOG_LINES: usize = 1_000;
const EVENT_CAPACITY: usize = 256;

#[derive(Clone, Debug)]
pub enum ConsoleLogEvent {
    Line(String),
    Clear,
}

#[derive(Clone)]
pub struct ConsoleLogBuffer {
    lines: Arc<Mutex<VecDeque<String>>>,
    events: broadcast::Sender<ConsoleLogEvent>,
}

impl ConsoleLogBuffer {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES))),
            events,
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let _ = self.events.send(ConsoleLogEvent::Clear);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConsoleLogEvent> {
        self.events.subscribe()
    }

    fn push(&self, line: String) {
        {
            let mut lines = self
                .lines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lines.len() == MAX_LOG_LINES {
                lines.pop_front();
            }
            lines.push_back(line.clone());
        }
        let _ = self.events.send(ConsoleLogEvent::Line(line));
    }
}

#[derive(Clone)]
pub struct ConsoleLogLayer {
    buffer: ConsoleLogBuffer,
}

impl ConsoleLogLayer {
    pub fn new(buffer: ConsoleLogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for ConsoleLogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);

        let message = fields.message.unwrap_or_default();
        let line = if fields.other.is_empty() {
            message
        } else if message.is_empty() {
            fields.other.join(" ")
        } else {
            format!("{message} {}", fields.other.join(" "))
        };
        self.buffer
            .push(format!("{} {line}", event.metadata().level()));
    }
}

#[derive(Default)]
struct EventFields {
    message: Option<String>,
    other: Vec<String>,
}

impl Visit for EventFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(value.trim_matches('"').to_owned());
        } else {
            self.other.push(format!("{}={value}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.other.push(format!("{}={value:?}", field.name()));
        }
    }
}
