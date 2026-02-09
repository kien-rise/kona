use crate::{
    Channel, HintReaderServer,
    errors::{PreimageOracleError, PreimageOracleResult},
    traits::{HintRouter, HintWriterClient},
};
use alloc::{boxed::Box, format, string::String, vec};
use async_trait::async_trait;

/// A [HintWriter] is a high-level interface to the hint channel. It provides a way to write hints
/// to the host.
#[derive(Debug, Clone, Copy)]
pub struct HintWriter<C> {
    channel: C,
}

impl<C> HintWriter<C> {
    /// Create a new [HintWriter] from a [Channel].
    pub const fn new(channel: C) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl<C> HintWriterClient for HintWriter<C>
where
    C: Channel + Send + Sync,
{
    /// Write a hint to the host. This will overwrite any existing hint in the channel, and block
    /// until all data has been written.
    async fn write(&self, hint: &[u8]) -> PreimageOracleResult<()> {
        trace!(target: "hint_writer", "Writing hint \"{hint:?}\"");

        // Form the hint into a byte buffer. The format is a 4-byte big-endian length prefix
        // followed by the hint string.
        self.channel.write(u32::to_be_bytes(hint.len() as u32).as_ref()).await?;
        self.channel.write(hint).await?;

        trace!(target: "hint_writer", "Successfully wrote hint");

        // Read the hint acknowledgement from the host.
        let mut hint_ack = [0u8; 1];
        self.channel.read_exact(&mut hint_ack).await?;

        trace!(target: "hint_writer", "Received hint acknowledgement");

        Ok(())
    }
}

/// A [HintReader] is a router for hints sent by the [HintWriter] from the client program. It
/// provides a way for the host to prepare preimages for reading.
#[derive(Debug, Clone, Copy)]
pub struct HintReader<C> {
    channel: C,
}

impl<C> HintReader<C>
where
    C: Channel,
{
    /// Create a new [HintReader] from a [Channel].
    pub const fn new(channel: C) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl<C> HintReaderServer for HintReader<C>
where
    C: Channel + Send + Sync,
{
    async fn next_hint<R>(&self, hint_router: &R) -> PreimageOracleResult<()>
    where
        R: HintRouter + Send + Sync,
    {
        // Read the length of the raw hint payload.
        let mut len_buf = [0u8; 4];
        self.channel.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        // Read the raw hint payload.
        let mut raw_payload = vec![0u8; len as usize];
        self.channel.read_exact(raw_payload.as_mut_slice()).await?;

        // TODO: reverse of crates/proof/proof/src/hint.rs
        // let payload = match String::from_utf8(raw_payload) {
        //     Ok(p) => p,
        //     Err(e) => {
        //         // Write back on error to prevent blocking the client.
        //         self.channel.write(&[0x00]).await?;

        //         return Err(PreimageOracleError::Other(format!(
        //             "Failed to decode hint payload: {e}"
        //         )));
        //     }
        // };

        trace!(target: "hint_reader", "Successfully read hint: \"{raw_payload:?}\"");

        // Route the hint
        if let Err(e) = hint_router.route_hint(raw_payload).await {
            // Write back on error to prevent blocking the client.
            self.channel.write(&[0x00]).await?;

            error!(target: "hint_reader", "Failed to route hint: {e}");
            return Err(e);
        }

        // Write back an acknowledgement to the client to unblock their process.
        self.channel.write(&[0x00]).await?;

        trace!(target: "hint_reader", "Successfully routed and acknowledged hint");

        Ok(())
    }
}
