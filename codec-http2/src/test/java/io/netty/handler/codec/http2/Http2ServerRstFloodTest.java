/*
 * Copyright 2025 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License, version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package io.netty.handler.codec.http2;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.InetSocketAddress;

import static io.netty.handler.codec.http2.Http2CodecUtil.FRAME_HEADER_LENGTH;
import static io.netty.handler.codec.http2.Http2CodecUtil.connectionPrefaceBuf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end regression test for the "MadeYouReset" HTTP/2 DDoS vector (CVE-2025-55163).
 *
 * <p>The inbound limiter added for CVE-2023-44487 ({@link Http2MaxRstFrameDecoder}) only counts {@code RST_STREAM}
 * frames <em>sent by the peer</em>. An attacker can side-step it completely by never sending a {@code RST_STREAM}
 * himself: he sends a perfectly valid request (so the server dispatches work for it) followed by a control frame
 * that is malformed in a way that only produces a <em>stream</em> error. The server then generates the
 * {@code RST_STREAM} itself, the inbound counter stays at zero, and the request/reset cycle can be repeated
 * without bound.
 *
 * <p>These tests drive a real server {@link Http2ConnectionHandler} through an {@link EmbeddedChannel}, replay each
 * of the frame vectors described by the advisory, and assert that the server eventually tears the connection down
 * with {@code GOAWAY(ENHANCE_YOUR_CALM)} instead of resetting streams forever.
 */
public class Http2ServerRstFloodTest {

    /**
     * Must be kept in sync with {@code DEFAULT_MAX_RST_FRAMES_PER_CONNECTION_FOR_SERVER} in
     * {@link AbstractHttp2ConnectionHandlerBuilder}, which is the limit that is enabled by default on servers.
     */
    private static final int DEFAULT_MAX_RST_FRAMES_PER_WINDOW_FOR_SERVER = 200;

    private static final int CONFIGURED_MAX_RST_FRAMES_PER_WINDOW = 10;

    private static final long NO_GO_AWAY = -1;

    /**
     * The frame vectors listed by the MadeYouReset advisory. Every one of them is accepted far enough for the
     * request to be processed, and every one of them makes the <em>server</em> emit the {@code RST_STREAM}.
     */
    public enum ResetVector {
        /**
         * {@code WINDOW_UPDATE} with an increment of {@code 0} on a request stream: stream error
         * {@code PROTOCOL_ERROR}.
         */
        WINDOW_UPDATE_ZERO_INCREMENT,

        /**
         * {@code WINDOW_UPDATE} whose increment overflows the outbound flow control window: stream error
         * {@code FLOW_CONTROL_ERROR}.
         */
        WINDOW_UPDATE_WINDOW_OVERFLOW,

        /**
         * {@code PRIORITY} frame with a payload length other than 5: stream error {@code FRAME_SIZE_ERROR}.
         */
        PRIORITY_INVALID_FRAME_LENGTH,

        /**
         * {@code DATA} frame on a stream that the client already half-closed with {@code END_STREAM}: stream error
         * {@code STREAM_CLOSED}.
         */
        DATA_AFTER_END_STREAM
    }

    private EmbeddedChannel channel;
    private Http2FrameInboundWriter inboundWriter;
    private ByteBuf outboundBytes;
    private int rstStreamFrames;
    private long goAwayErrorCode = NO_GO_AWAY;

    @AfterEach
    public void tearDown() {
        if (outboundBytes != null) {
            outboundBytes.release();
            outboundBytes = null;
        }
        if (channel != null) {
            channel.close();
            releaseAll(true);
            releaseAll(false);
            channel = null;
        }
        inboundWriter = null;
    }

    @ParameterizedTest
    @EnumSource(ResetVector.class)
    public void serverEnforcesDefaultLimitOnSelfGeneratedResets(ResetVector vector) throws Exception {
        setUp(null);
        assertFloodIsThrottled(vector, DEFAULT_MAX_RST_FRAMES_PER_WINDOW_FOR_SERVER);
    }

    @ParameterizedTest
    @EnumSource(ResetVector.class)
    public void serverEnforcesConfiguredLimitOnSelfGeneratedResets(ResetVector vector) throws Exception {
        setUp(CONFIGURED_MAX_RST_FRAMES_PER_WINDOW);
        assertFloodIsThrottled(vector, CONFIGURED_MAX_RST_FRAMES_PER_WINDOW);
    }

    /**
     * Negative control which pins down the vulnerable behaviour: with the encoder side limit switched off the
     * server happily answers every single request with a {@code RST_STREAM} and never gives up, because the
     * inbound {@link Http2MaxRstFrameDecoder} limiter never observes a client sent {@code RST_STREAM}.
     */
    @ParameterizedTest
    @EnumSource(ResetVector.class)
    public void serverFloodsResetsWhenLimitIsDisabled(ResetVector vector) throws Exception {
        setUp(0);
        int requests = DEFAULT_MAX_RST_FRAMES_PER_WINDOW_FOR_SERVER * 2 + 10;
        assertEquals(requests, flood(vector, requests), "Connection was torn down unexpectedly");
        assertEquals(requests, rstStreamFrames,
                "Every request should have been answered with exactly one server generated RST_STREAM");
        assertEquals(NO_GO_AWAY, goAwayErrorCode, "Server unexpectedly sent a GOAWAY while the limit is disabled");
        assertTrue(channel.isOpen(), "Connection should still be open while the limit is disabled");
    }

    private void assertFloodIsThrottled(ResetVector vector, int maxRstFramesPerWindow) {
        flood(vector, maxRstFramesPerWindow * 2 + 10);

        assertEquals(Http2Error.ENHANCE_YOUR_CALM.code(), goAwayErrorCode,
                "Server did not send a GOAWAY with ENHANCE_YOUR_CALM after " + rstStreamFrames
                        + " RST_STREAM frames");
        assertEquals(maxRstFramesPerWindow + 1, rstStreamFrames,
                "Server should stop after exceeding the configured RST_STREAM limit");
        assertFalse(channel.isOpen(), "Connection should have been closed once the RST_STREAM limit was exceeded");
    }

    private void setUp(Integer maxRstFramesPerWindow) throws Exception {
        Http2ConnectionHandlerBuilder builder = new Http2ConnectionHandlerBuilder()
                .server(true)
                .frameListener(new Http2FrameAdapter());
        if (maxRstFramesPerWindow != null) {
            builder.encoderEnforceMaxRstFramesPerWindow(maxRstFramesPerWindow, 30);
        }
        Http2ConnectionHandler handler = builder.build();

        outboundBytes = Unpooled.buffer();
        channel = new EmbeddedChannel();
        inboundWriter = new Http2FrameInboundWriter(channel);
        channel.connect(new InetSocketAddress(0));
        channel.pipeline().addLast(handler);
        channel.pipeline().fireChannelActive();

        // HTTP/2 handshake: client connection preface followed by the client SETTINGS frame.
        channel.writeInbound(connectionPrefaceBuf());
        inboundWriter.writeInboundSettings(new Http2Settings());
        drainOutbound();

        assertEquals(0, rstStreamFrames, "Handshake must not produce any RST_STREAM frame");
        assertEquals(NO_GO_AWAY, goAwayErrorCode, "Handshake must not produce a GOAWAY frame");
    }

    /**
     * Replays {@code requests} MadeYouReset request/reset cycles and returns how many of them the server accepted
     * before it closed the connection.
     */
    private int flood(ResetVector vector, int requests) {
        int streamId = 1;
        int accepted = 0;
        for (int i = 0; i < requests; i++) {
            if (!channel.isOpen()) {
                break;
            }
            try {
                sendResetTrigger(vector, streamId);
            } catch (Throwable cause) {
                // The server tore the connection down while we were still writing, which is exactly what the
                // limiter is supposed to do.
                break;
            } finally {
                streamId += 2;
            }
            accepted++;
            drainOutbound();
        }
        drainOutbound();
        return accepted;
    }

    private void sendResetTrigger(ResetVector vector, int streamId) {
        Http2Headers headers = new DefaultHttp2Headers()
                .method("GET").scheme("https").authority("example.org").path("/");
        switch (vector) {
            case WINDOW_UPDATE_ZERO_INCREMENT:
                inboundWriter.writeInboundHeaders(streamId, headers, 0, false);
                // A WINDOW_UPDATE with a 0 increment on a request stream is a stream error, the frame writer
                // refuses to produce it so the raw frame is hand-crafted here.
                inboundWriter.writeInboundFrame(Http2FrameTypes.WINDOW_UPDATE, streamId, new Http2Flags(),
                        Unpooled.buffer(4).writeInt(0));
                break;
            case WINDOW_UPDATE_WINDOW_OVERFLOW:
                inboundWriter.writeInboundHeaders(streamId, headers, 0, false);
                // Overflows the outbound flow control window of the stream.
                inboundWriter.writeInboundWindowUpdate(streamId, Integer.MAX_VALUE);
                break;
            case PRIORITY_INVALID_FRAME_LENGTH:
                inboundWriter.writeInboundHeaders(streamId, headers, 0, false);
                // A PRIORITY frame must be exactly 5 bytes long, anything else is a stream error.
                inboundWriter.writeInboundFrame(Http2FrameTypes.PRIORITY, streamId, new Http2Flags(),
                        Unpooled.buffer(4).writeInt(0));
                break;
            case DATA_AFTER_END_STREAM:
                // A complete request half-closes the stream ...
                inboundWriter.writeInboundHeaders(streamId, headers, 0, true);
                // ... and a DATA frame on the half-closed stream is a stream error.
                inboundWriter.writeInboundData(streamId, Unpooled.buffer(1).writeByte('x'), 0, false);
                break;
            default:
                throw new IllegalArgumentException("Unknown reset vector: " + vector);
        }
    }

    private void drainOutbound() {
        for (;;) {
            Object msg = channel.readOutbound();
            if (msg == null) {
                break;
            }
            if (msg instanceof ByteBuf) {
                ByteBuf buf = (ByteBuf) msg;
                try {
                    outboundBytes.writeBytes(buf);
                } finally {
                    buf.release();
                }
            } else {
                ReferenceCountUtil.release(msg);
            }
        }
        parseOutboundFrames();
    }

    /**
     * Parses whatever complete HTTP/2 frames the server produced so far and keeps track of the number of
     * {@code RST_STREAM} frames and of the error code of the first {@code GOAWAY}.
     */
    private void parseOutboundFrames() {
        while (outboundBytes.readableBytes() >= FRAME_HEADER_LENGTH) {
            int payloadLength = outboundBytes.getUnsignedMedium(outboundBytes.readerIndex());
            if (outboundBytes.readableBytes() < FRAME_HEADER_LENGTH + payloadLength) {
                break;
            }
            outboundBytes.skipBytes(3);
            byte frameType = outboundBytes.readByte();
            outboundBytes.skipBytes(1); // flags
            outboundBytes.skipBytes(4); // stream id
            int payloadEnd = outboundBytes.readerIndex() + payloadLength;
            if (frameType == Http2FrameTypes.RST_STREAM) {
                rstStreamFrames++;
            } else if (frameType == Http2FrameTypes.GO_AWAY && goAwayErrorCode == NO_GO_AWAY) {
                // GOAWAY payload: 4 bytes last stream id, 4 bytes error code, then the debug data.
                goAwayErrorCode = outboundBytes.getUnsignedInt(outboundBytes.readerIndex() + 4);
            }
            outboundBytes.readerIndex(payloadEnd);
        }
        outboundBytes.discardReadBytes();
    }

    private void releaseAll(boolean inbound) {
        for (;;) {
            Object msg = inbound ? channel.readInbound() : channel.readOutbound();
            if (msg == null) {
                return;
            }
            ReferenceCountUtil.release(msg);
        }
    }
}
