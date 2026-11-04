use super::{Command, Pointer};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Mouse, Settings};

pub(super) struct NativePointer {
    enigo: Enigo,
    left: bool,
    right: bool,
    movement: (f64, f64),
    scroll: (f64, f64),
}

impl NativePointer {
    pub(super) fn open() -> Result<Self, String> {
        Ok(Self {
            enigo: Enigo::new(&Settings::default()).map_err(|error| error.to_string())?,
            left: false,
            right: false,
            movement: (0.0, 0.0),
            scroll: (0.0, 0.0),
        })
    }

    fn click(&mut self, button: Button) -> Result<(), String> {
        match button {
            Button::Left => self.left = true,
            Button::Right => self.right = true,
            _ => {}
        }
        self.enigo
            .button(button, Direction::Click)
            .map_err(|error| error.to_string())?;
        match button {
            Button::Left => self.left = false,
            Button::Right => self.right = false,
            _ => {}
        }
        Ok(())
    }
}

impl Pointer for NativePointer {
    fn apply(&mut self, command: Command) -> Result<(), String> {
        if !command.valid() {
            return Err("invalid pointer displacement".to_owned());
        }
        match command {
            Command::Move { dx, dy } => {
                self.movement.0 += dx;
                self.movement.1 += dy;
                let x = self.movement.0.trunc() as i32;
                let y = self.movement.1.trunc() as i32;
                self.movement.0 -= f64::from(x);
                self.movement.1 -= f64::from(y);
                self.enigo
                    .move_mouse(x, y, Coordinate::Rel)
                    .map_err(|error| error.to_string())
            }
            Command::Scroll { dx, dy } => {
                self.scroll.0 -= dx / 40.0;
                self.scroll.1 -= dy / 40.0;
                let x = self.scroll.0.trunc() as i32;
                let y = self.scroll.1.trunc() as i32;
                self.scroll.0 -= f64::from(x);
                self.scroll.1 -= f64::from(y);
                if x != 0 {
                    self.enigo
                        .scroll(x, Axis::Horizontal)
                        .map_err(|error| error.to_string())?;
                }
                if y != 0 {
                    self.enigo
                        .scroll(y, Axis::Vertical)
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            }
            Command::LeftClick => self.click(Button::Left),
            Command::RightClick => self.click(Button::Right),
            Command::LeftDown => {
                if self.left {
                    return Err("the left button is already held".to_owned());
                }
                self.left = true;
                self.enigo
                    .button(Button::Left, Direction::Press)
                    .map_err(|error| error.to_string())
            }
            Command::LeftUp => self.release(),
        }
    }

    fn release(&mut self) -> Result<(), String> {
        if self.left {
            self.enigo
                .button(Button::Left, Direction::Release)
                .map_err(|error| error.to_string())?;
            self.left = false;
        }
        if self.right {
            self.enigo
                .button(Button::Right, Direction::Release)
                .map_err(|error| error.to_string())?;
            self.right = false;
        }
        Ok(())
    }
}

impl Drop for NativePointer {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
