#![no_main]

use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_application_message, decode_conversation_state,
    decode_device_credential_binding, decode_invitation, decode_join_proof,
    decode_membership_change, decode_relay_envelope, decode_replay_page, decode_replay_request,
    decode_stored_relay_envelope,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = decode_application_message(bytes);
    let _ = decode_device_credential_binding(bytes);
    let _ = decode_invitation(bytes);
    let _ = decode_join_proof(bytes);
    let _ = decode_conversation_state(bytes);
    let _ = decode_membership_change(bytes);
    let _ = decode_relay_envelope(bytes);
    let _ = decode_stored_relay_envelope(bytes);
    let _ = decode_replay_request(bytes);
    let _ = decode_replay_page(bytes);
    let _ = decode_acknowledge_request(bytes);
});
