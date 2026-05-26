//! No-op SPEL program: reads pre_states, returns them as post_states,
//! writes no state changes. Used as the chained-call target for the
//! LP-0002 step-7 e2e test — `execute` fires this from the verifier
//! once threshold is reached, and the test observes the call landed
//! without needing any side effects to model.
//!
//! Modelled on `logos-execution-zone/test_program_methods/guest/src/bin/noop.rs`
//! at tag v0.2.0-rc3. Kept local rather than vendored so the e2e
//! crate stays self-contained and no LEZ binary artifacts are committed.

use nssa_core::program::{read_nssa_inputs, AccountPostState, ProgramInput, ProgramOutput};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
