//! Typed guest entry points, with result ownership and post-return cleanup.

use wasmtime::component::{ComponentNamedList, Func, Lift, Lower};

use super::bindings::synra::plugin::types::Outcome;
use super::{CallFailure, EngineInstance, export_name, interface_name};
use crate::engine::types::{CallOutcome, Work};

impl EngineInstance {
    pub(super) fn dispatch(&mut self, work: &Work) -> Result<CallOutcome, CallFailure> {
        let interface = work.interface();
        let function = work.function();
        let qualified = interface_name(interface);
        let nested = self
            .instance
            .get_export_index(&mut self.store, None, &qualified)
            .and_then(|index| {
                self.instance
                    .get_export_index(&mut self.store, Some(&index), function)
            })
            .and_then(|index| self.instance.get_func(&mut self.store, index));
        let export = nested
            .or_else(|| {
                self.instance
                    .get_func(&mut self.store, export_name(interface, function))
            })
            .ok_or(CallFailure::MissingExport {
                interface,
                function,
            })?;
        match work {
            Work::Event { event_json } => {
                let (answer,) = self.invoke::<_, (Outcome,)>(export, (event_json.as_str(),))?;
                Ok(outcome(answer))
            }
            Work::Deactivate => {
                self.invoke::<(), ()>(export, ())?;
                Ok(CallOutcome::Ok(String::new()))
            }
            Work::CanHandle { item_json } => {
                let (answer,) = self.invoke::<_, (String,)>(export, (item_json.as_str(),))?;
                Ok(CallOutcome::Ok(answer))
            }
            Work::Activate { config_json } => {
                let (answer,) = self.invoke::<_, (Outcome,)>(export, (config_json.as_str(),))?;
                Ok(outcome(answer))
            }
            Work::Tick { tick_json } => {
                let (answer,) = self.invoke::<_, (Outcome,)>(export, (tick_json.as_str(),))?;
                Ok(outcome(answer))
            }
            Work::Migrate {
                from_version,
                to_version,
            } => {
                let (answer,) = self.invoke::<_, (Outcome,)>(
                    export,
                    (from_version.as_str(), to_version.as_str()),
                )?;
                Ok(outcome(answer))
            }
            Work::Execute { action, args_json } => {
                let (answer,) =
                    self.invoke::<_, (Outcome,)>(export, (action.as_str(), args_json.as_str()))?;
                Ok(outcome(answer))
            }
            Work::InvokeAction { name, args_json } => {
                let (answer,) =
                    self.invoke::<_, (Outcome,)>(export, (name.as_str(), args_json.as_str()))?;
                Ok(outcome(answer))
            }
        }
    }

    fn invoke<P, R>(&mut self, export: Func, params: P) -> Result<R, CallFailure>
    where
        P: ComponentNamedList + Lower,
        R: ComponentNamedList + Lift,
    {
        // Type-check before executing guest code; a mismatched ABI must not perform side effects.
        let export = export
            .typed::<P, R>(&self.store)
            .map_err(CallFailure::Trap)?;
        let results = export
            .call(&mut self.store, params)
            .map_err(CallFailure::Trap)?;
        export
            .post_return(&mut self.store)
            .map_err(CallFailure::Trap)?;
        Ok(results)
    }
}

fn outcome(answer: Outcome) -> CallOutcome {
    match answer {
        Outcome::Ok(payload) => CallOutcome::Ok(payload),
        Outcome::Err(error) => CallOutcome::Failed {
            code: error.code,
            message: error.message,
            details: error.details,
        },
    }
}
#[cfg(test)]
mod tests;
