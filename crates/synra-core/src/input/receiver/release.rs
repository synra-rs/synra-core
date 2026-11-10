use synra_platform::pointer::Pointer;

pub(in crate::input::receiver) struct Released(pub(in crate::input::receiver) Box<dyn Pointer>);
impl Drop for Released {
    fn drop(&mut self) {
        let _ = self.0.release();
    }
}
