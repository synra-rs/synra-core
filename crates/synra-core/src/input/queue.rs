use super::Command;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::time::Instant;

pub(super) struct Sample {
    pub(super) commands: Vec<Command>,
    pub(super) at: Instant,
}

#[derive(Default)]
pub(super) struct Queue(Mutex<VecDeque<Sample>>);

impl Queue {
    pub(super) fn push(&self, commands: Vec<Command>) -> Result<(), String> {
        if commands.len() > 16 || !commands.iter().all(|command| command.valid()) {
            return Err("invalid pointer commands".to_owned());
        }
        if commands.is_empty() {
            return Ok(());
        }
        let mut queue = self.0.lock();
        if let ([next], Some(last)) = (commands.as_slice(), queue.back_mut())
            && let [previous] = last.commands.as_mut_slice()
        {
            let merged = match (*previous, *next) {
                (Command::Move { dx: ax, dy: ay }, Command::Move { dx: bx, dy: by }) => {
                    Some(Command::Move {
                        dx: ax + bx,
                        dy: ay + by,
                    })
                }
                (Command::Scroll { dx: ax, dy: ay }, Command::Scroll { dx: bx, dy: by }) => {
                    Some(Command::Scroll {
                        dx: ax + bx,
                        dy: ay + by,
                    })
                }
                _ => None,
            };
            if let Some(merged) = merged.filter(|command| command.valid()) {
                *previous = merged;
                return Ok(());
            }
        }
        if queue.len() >= 64 {
            return Err("input queue overflow".to_owned());
        }
        queue.push_back(Sample {
            commands,
            at: Instant::now(),
        });
        drop(queue);
        Ok(())
    }

    pub(super) fn pop(&self) -> Option<Sample> {
        self.0.lock().pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn motion_accumulates_without_crossing_a_button_boundary() {
        let queue = Queue::default();
        queue
            .push(vec![Command::Move { dx: 2.0, dy: -1.0 }])
            .unwrap();
        queue
            .push(vec![Command::Move { dx: 3.0, dy: -2.0 }])
            .unwrap();
        queue.push(vec![Command::LeftDown]).unwrap();
        queue
            .push(vec![Command::Move { dx: 4.0, dy: 0.0 }])
            .unwrap();
        queue.push(vec![Command::LeftUp]).unwrap();
        assert_eq!(
            queue.pop().unwrap().commands,
            vec![Command::Move { dx: 5.0, dy: -3.0 }]
        );
        assert_eq!(queue.pop().unwrap().commands, vec![Command::LeftDown]);
        assert_eq!(
            queue.pop().unwrap().commands,
            vec![Command::Move { dx: 4.0, dy: 0.0 }]
        );
        assert_eq!(queue.pop().unwrap().commands, vec![Command::LeftUp]);
    }
}
