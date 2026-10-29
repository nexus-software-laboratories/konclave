use super::*;

const MAGIC: &[u8; 8] = b"KNSJNL01";

struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        if self.0.len().saturating_add(bytes.len()) > MAX_BYTES {
            return Err(JournalError::Capacity);
        }
        self.0.try_reserve(bytes.len()).map_err(|_| JournalError::Capacity)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn number(&mut self, value: u64) -> Result<(), JournalError> {
        self.raw(&value.to_be_bytes())
    }
    fn flag(&mut self, value: bool) -> Result<(), JournalError> {
        self.raw(&[u8::from(value)])
    }
    fn field(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        if bytes.is_empty() || bytes.len() > MAX_FIELD { return Err(JournalError::Capacity); }
        self.number(bytes.len() as u64)?;
        self.raw(bytes)
    }
    fn optional_number(&mut self, number: Option<u64>) -> Result<(), JournalError> {
        self.flag(number.is_some())?;
        if let Some(number) = number { self.number(number)?; }
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn raw(&mut self, length: usize) -> Result<&'a [u8], JournalError> {
        if length > self.0.len() { return Err(JournalError::Invalid); }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }
    fn number(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.raw(8)?.try_into().map_err(|_| JournalError::Invalid)?))
    }
    fn flag(&mut self) -> Result<bool, JournalError> {
        match self.raw(1)? {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(JournalError::Invalid),
        }
    }
    fn count(&mut self, maximum: usize) -> Result<usize, JournalError> {
        let value = usize::try_from(self.number()?).map_err(|_| JournalError::Capacity)?;
        if value > maximum { return Err(JournalError::Capacity); }
        Ok(value)
    }
    fn field(&mut self) -> Result<&'a [u8], JournalError> {
        let length = self.count(MAX_FIELD)?;
        if length == 0 { return Err(JournalError::Invalid); }
        self.raw(length)
    }
    fn optional_number(&mut self) -> Result<Option<u64>, JournalError> {
        if self.flag()? { Ok(Some(self.number()?)) } else { Ok(None) }
    }
}

pub(super) fn encode(snapshot: &Snapshot) -> Result<Zeroizing<Vec<u8>>, JournalError> {
    let mut writer = Writer(Zeroizing::new(Vec::new()));
    writer.raw(MAGIC)?;
    writer.field(snapshot.identity.as_bytes())?;
    writer.field(snapshot.signing.as_bytes())?;
    writer.field(snapshot.endpoint.as_str().as_bytes())?;
    writer.field(snapshot.credential.as_bytes())?;
    let policy = Zeroizing::new(encode_conversation_state(&snapshot.state).map_err(|_| JournalError::Invalid)?);
    writer.field(&policy)?;
    writer.number(snapshot.bindings.len() as u64)?;
    for binding in &snapshot.bindings {
        let bytes = Zeroizing::new(encode_device_credential_binding(binding).map_err(|_| JournalError::Invalid)?);
        writer.field(&bytes)?;
    }
    writer.raw(snapshot.route.as_bytes())?;
    writer.number(snapshot.counter)?;
    writer.number(snapshot.cursor)?;
    writer.raw(snapshot.authority.conversation.as_bytes())?;
    writer.raw(snapshot.authority.device.as_bytes())?;
    writer.number(snapshot.authority.revision)?;
    writer.flag(snapshot.authority.enabled)?;
    writer.number(snapshot.authority.claims.len() as u64)?;
    for claim in &snapshot.authority.claims {
        writer.raw(&claim.id)?;
        writer.raw(claim.request.as_bytes())?;
        writer.raw(claim.requester.as_bytes())?;
        writer.flag(claim.response.is_some())?;
        if let Some(response) = claim.response {
            writer.raw(response.message.as_bytes())?;
            writer.raw(response.envelope.as_bytes())?;
        }
    }
    writer.number(snapshot.outbox.len() as u64)?;
    for row in &snapshot.outbox {
        writer.raw(row.reservation.message_id.as_bytes())?;
        writer.raw(row.reservation.envelope_id.as_bytes())?;
        writer.number(row.reservation.sender_counter)?;
        writer.number(row.epoch)?;
        writer.number(row.expiry)?;
        writer.field(&row.intent)?;
        writer.flag(row.saved)?;
        writer.flag(row.envelope.is_some())?;
        if let Some(envelope) = &row.envelope {
            writer.field(&encode_relay_envelope(envelope).map_err(|_| JournalError::Invalid)?)?;
        }
        writer.flag(row.abandoned)?;
        writer.optional_number(row.accepted)?;
        writer.flag(row.expired)?;
    }
    writer.number(snapshot.inbox.len() as u64)?;
    for row in &snapshot.inbox {
        writer.field(&encode_stored_relay_envelope(&row.stored).map_err(|_| JournalError::Invalid)?)?;
        writer.number(row.epoch)?;
        writer.flag(row.message.is_some())?;
        if let Some(message) = &row.message {
            writer.raw(row.sender.ok_or(JournalError::Invalid)?.as_bytes())?;
            writer.field(message)?;
        }
        writer.flag(row.notification.is_some())?;
        if let Some((notification, now)) = row.notification {
            writer.raw(notification.as_bytes())?;
            writer.number(now)?;
        }
    }
    Ok(writer.0)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Snapshot, JournalError> {
    if bytes.len() > MAX_BYTES { return Err(JournalError::Capacity); }
    let mut reader = Reader(bytes);
    if reader.raw(8)? != MAGIC { return Err(JournalError::Invalid); }
    let identity = SealedBlob::from_bytes(reader.field()?.to_vec()).map_err(|_| JournalError::Invalid)?;
    let signing = SealedBlob::from_bytes(reader.field()?.to_vec()).map_err(|_| JournalError::Invalid)?;
    let endpoint_bytes = reader.field()?;
    if endpoint_bytes.len() > 4096 { return Err(JournalError::Capacity); }
    let endpoint_text = std::str::from_utf8(endpoint_bytes).map_err(|_| JournalError::Invalid)?;
    let endpoint = RelayEndpoint::parse(endpoint_text).map_err(|_| JournalError::Invalid)?;
    if endpoint.as_str() != endpoint_text { return Err(JournalError::Invalid); }
    let credential = SealedBlob::from_bytes(reader.field()?.to_vec()).map_err(|_| JournalError::Invalid)?;
    let state_bytes = reader.field()?;
    let state = decode_conversation_state(state_bytes).map_err(|_| JournalError::Invalid)?;
    let canonical = Zeroizing::new(encode_conversation_state(&state).map_err(|_| JournalError::Invalid)?);
    if canonical.as_slice() != state_bytes { return Err(JournalError::Invalid); }
    let mut bindings = Vec::new();
    for _ in 0..reader.count(MAX_MEMBERS)? {
        let bytes = reader.field()?;
        let binding = decode_device_credential_binding(bytes).map_err(|_| JournalError::Invalid)?;
        let canonical = Zeroizing::new(encode_device_credential_binding(&binding).map_err(|_| JournalError::Invalid)?);
        if canonical.as_slice() != bytes { return Err(JournalError::Invalid); }
        bindings.push(binding);
    }
    let route = RoutingId::from_slice(reader.raw(RoutingId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
    let counter = reader.number()?;
    let cursor = reader.number()?;
    let conversation = ConversationId::from_slice(reader.raw(ConversationId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
    let device = DeviceId::from_slice(reader.raw(DeviceId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
    let revision = reader.number()?;
    let enabled = reader.flag()?;
    let mut claims = Vec::new();
    for _ in 0..reader.count(MAX_CLAIMS)? {
        let id = reader.raw(16)?.try_into().map_err(|_| JournalError::Invalid)?;
        let request = MessageId::from_slice(reader.raw(MessageId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
        let requester = DeviceId::from_slice(reader.raw(DeviceId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
        let response = if reader.flag()? {
            Some(CommittedResponse {
                message: MessageId::from_slice(reader.raw(MessageId::LENGTH)?).map_err(|_| JournalError::Invalid)?,
                envelope: EnvelopeId::from_slice(reader.raw(EnvelopeId::LENGTH)?).map_err(|_| JournalError::Invalid)?,
            })
        } else { None };
        claims.push(HandlingClaim { id, request, requester, response });
    }
    let authority = ServiceAuthority { conversation, device, revision, enabled, claims };
    let mut outbox = Vec::new();
    for _ in 0..reader.count(MAX_ROWS)? {
        let message_id = MessageId::from_slice(reader.raw(MessageId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
        let envelope_id = EnvelopeId::from_slice(reader.raw(EnvelopeId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
        let sender_counter = reader.number()?;
        let epoch = reader.number()?;
        let expiry = reader.number()?;
        let intent = Zeroizing::new(reader.field()?.to_vec());
        let saved = reader.flag()?;
        let envelope = if reader.flag()? {
            let bytes = reader.field()?;
            let envelope = decode_relay_envelope(bytes).map_err(|_| JournalError::Invalid)?;
            if encode_relay_envelope(&envelope).map_err(|_| JournalError::Invalid)? != bytes {
                return Err(JournalError::Invalid);
            }
            Some(envelope)
        } else { None };
        let abandoned = reader.flag()?;
        let accepted = reader.optional_number()?;
        let expired = reader.flag()?;
        outbox.push(Outbox {
            reservation: OutboundReservation { conversation_id: conversation, message_id, envelope_id, sender_counter },
            epoch, expiry, intent, saved, envelope, abandoned, accepted, expired,
        });
    }
    let mut inbox = Vec::new();
    for _ in 0..reader.count(MAX_ROWS)? {
        let bytes = reader.field()?;
        let stored = decode_stored_relay_envelope(bytes).map_err(|_| JournalError::Invalid)?;
        if encode_stored_relay_envelope(&stored).map_err(|_| JournalError::Invalid)? != bytes {
            return Err(JournalError::Invalid);
        }
        let epoch = reader.number()?;
        let (sender, message) = if reader.flag()? {
            let sender = DeviceId::from_slice(reader.raw(DeviceId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
            (Some(sender), Some(Zeroizing::new(reader.field()?.to_vec())))
        } else { (None, None) };
        let notification = if reader.flag()? {
            let id = NotificationId::from_slice(reader.raw(NotificationId::LENGTH)?).map_err(|_| JournalError::Invalid)?;
            Some((id, reader.number()?))
        } else { None };
        inbox.push(Inbox { stored, sender, epoch, message, notification });
    }
    if !reader.0.is_empty() { return Err(JournalError::Invalid); }
    Ok(Snapshot { identity, signing, endpoint, credential, state, bindings, route, counter, cursor, authority, outbox, inbox })
}
