package com.mayreh.jktls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.ScatteringByteChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;

import com.mayreh.jktls.sun.nio.ch.FileChannelImpl;
import com.mayreh.jktls.sun.nio.ch.SocketChannelImpl;
import com.mayreh.jktls.tls.tls12_crypto_info_aes_gcm_128;
import com.mayreh.jktls.tls.tls_crypto_info;

import static com.mayreh.jktls.tls.tls_h.TLS_1_2_VERSION;
import static com.mayreh.jktls.tls.tls_h.TLS_CIPHER_AES_GCM_128;

/**
 * A wrapper around {@link SocketChannel} with some tweaks to utilize kernel TLS.
 */
public class KTlsSocketChannel implements ByteChannel,
                                          ScatteringByteChannel,
                                          GatheringByteChannel,
                                          NetworkChannel {
    KTlsSocketChannel(SocketChannel delegate, SocketChannelImpl impl) {
        this.delegate = delegate;
        this.impl = impl;
    }

    private static int SOL_TCP = 6;
    private static int SOL_TLS = 282;
    private static int TCP_ULP = 31;
    private static int TLS_TX = 1;

    private static final Linker.Option ccs = Linker.Option.captureCallState("errno");
    private static final StructLayout capturedStateLayout = Linker.Option.captureStateLayout();
    private static final VarHandle errnoHandle = capturedStateLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    private static final MethodHandle setsockoptHandle;
    private static final MethodHandle sendfile64Handle;
    private static final MethodHandle strerror;
    static {
        Linker linker = Linker.nativeLinker();
        SymbolLookup stdLib = linker.defaultLookup();
        MemorySegment sendfile64Address = stdLib.find("sendfile64")
                .orElseThrow(() -> new RuntimeException("sendfile64 not found"));
        FunctionDescriptor sendfile64Descriptor = FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG
        );
        sendfile64Handle = linker.downcallHandle(sendfile64Address, sendfile64Descriptor, ccs);
        MemorySegment setsockoptAddress = stdLib.find("setsockopt")
                .orElseThrow(() -> new RuntimeException("setsockopt not found"));
        FunctionDescriptor setsockoptDescriptor = FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT
        );
        setsockoptHandle = linker.downcallHandle(setsockoptAddress, setsockoptDescriptor, ccs);

        strerror = linker.downcallHandle(
                stdLib.find("strerror").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    private static void setTcpUlp(int fd, String name) throws SocketException {
        try (var arena = Arena.ofConfined()) {
            MemorySegment capturedState = arena.allocate(capturedStateLayout);
            var n = arena.allocateFrom(name);
            int ret = (int) setsockoptHandle.invoke(
                    capturedState,
                    fd,
                    SOL_TCP,
                    TCP_ULP,
                    n,
                    Math.toIntExact(n.byteSize())
            );
            if (ret == -1) {
                String errorString = errnoCode(errnoHandle, capturedState, strerror);
                throw new RuntimeException("Failed to set TCP_ULP: " + errorString);
            }
        } catch (SocketException s) {
            throw s;
        } catch (Error | RuntimeException ex) {
            throw ex;
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static void setTlsTx(
            int fd, String protocol, String cipherSuite, byte[] iv, byte[] key, byte[] salt, byte[] recSeq) throws SocketException {
        try (var arena = Arena.ofConfined()) {
            MemorySegment capturedState = arena.allocate(capturedStateLayout);
            MemorySegment m = switch (protocol) {
                case "TLSv1.2" -> switch (cipherSuite) {
                    case "TLS_RSA_WITH_AES_128_GCM_SHA256" -> {
                        var struct = tls12_crypto_info_aes_gcm_128.allocate(arena);

                        var info = tls12_crypto_info_aes_gcm_128.info(struct);
                        tls_crypto_info.version(info, (short) TLS_1_2_VERSION());
                        tls_crypto_info.cipher_type(info, (short) TLS_CIPHER_AES_GCM_128());
                        tls12_crypto_info_aes_gcm_128.info(struct);
                        tls12_crypto_info_aes_gcm_128.iv(struct).asByteBuffer().put(iv);
                        tls12_crypto_info_aes_gcm_128.key(struct).asByteBuffer().put(key);
                        tls12_crypto_info_aes_gcm_128.salt(struct).asByteBuffer().put(salt);
                        tls12_crypto_info_aes_gcm_128.rec_seq(struct).asByteBuffer().put(recSeq);

                        yield struct;
                    }
                    default ->
                            throw new UnsupportedOperationException("Unsupported: protocol=" + protocol + ", cipherSuite=" + cipherSuite);
                };
                default ->
                        throw new UnsupportedOperationException("Unsupported: protocol=" + protocol + ", cipherSuite=" + cipherSuite);
            };
            int ret = (int) setsockoptHandle.invoke(
                    capturedState,
                    fd,
                    SOL_TLS,
                    TLS_TX,
                    m,
                    Math.toIntExact(m.byteSize())
            );
            if (ret == -1) {
                String errorString = errnoCode(errnoHandle, capturedState, strerror);
                throw new SocketException("Failed to set TLS_TX: " + errorString);
            }
        } catch (SocketException s) {
            throw s;
        } catch (Error | RuntimeException ex) {
            throw ex;
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static long sendFile(int outFd, int inFd, long position, long count) throws SocketException {
        try (var arena = Arena.ofConfined()) {
            MemorySegment capturedState = arena.allocate(capturedStateLayout);
            var ret = (long) sendfile64Handle.invokeExact(capturedState, outFd, inFd, MemorySegment.ofAddress(position), count);
            if (ret == -1) {
                String errorString = errnoCode(errnoHandle, capturedState, strerror);
                throw new SocketException("Failed to send file: " + errorString);
            }
            return ret;
        } catch (SocketException s) {
            throw new RuntimeException(s);
        } catch (Error | RuntimeException ex) {
            throw ex;
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static String errnoCode(
            VarHandle errnoHandle,
            MemorySegment capturedState,
            MethodHandle strerror) throws Throwable {

        // Get more information by consulting the value of errno:
        int errno = (int) errnoHandle.get(capturedState, 0);

        // An errno value of 2 (ENOENT) is "No such file or directory"
        System.out.println("errno: " + errno);

        // Convert errno code to a string message:
        String errorString = ((MemorySegment) strerror.invokeExact(errno))
                .reinterpret(Long.MAX_VALUE).getString(0);
        System.out.println("errno string: " + errorString);

        return errorString;
    }

    private final SocketChannel delegate;
    private final SocketChannelImpl impl;

    public static KTlsSocketChannel wrap(SocketChannel channel) {
        if (!SocketChannelImpl.isInstance(channel)) {
            throw new UnsupportedOperationException("Unsupported SocketChannel implementation");
        }
        return new KTlsSocketChannel(channel, new SocketChannelImpl(channel));
    }

    public long transferFrom(FileChannel channel, long position, long count) throws IOException {
        if (FileChannelImpl.isInstance(channel)) {
            FileChannelImpl fileChannel = new FileChannelImpl(channel);
            return sendFile(FDUtil.fdVal(impl.getFD()),
                            FDUtil.fdVal(fileChannel.fd()),
                            position,
                            count);
        }
        throw new UnsupportedOperationException("Unsupported FileChannel implementation");
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        return delegate.write(srcs, offset, length);
    }

    @Override
    public long write(ByteBuffer[] srcs) throws IOException {
        return delegate.write(srcs);
    }

    @Override
    public KTlsSocketChannel bind(SocketAddress local) throws IOException {
        delegate.bind(local);
        return this;
    }

    @Override
    public SocketAddress getLocalAddress() throws IOException {
        return delegate.getLocalAddress();
    }

    @Override
    public <T> KTlsSocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        if (name == KTlsSocketOptions.TCP_ULP) {
            setTcpUlp(FDUtil.fdVal(impl.getFD()), (String) value);
            return this;
        }
        if (name == KTlsSocketOptions.TLS_TX) {
            TlsCryptoInfo info = (TlsCryptoInfo) value;
            setTlsTx(FDUtil.fdVal(impl.getFD()),
                     info.protocol(),
                     info.cipherSuite(),
                     info.iv(),
                     info.key(),
                     info.salt(),
                     info.recSeq());
            return this;
        }
        delegate.setOption(name, value);
        return this;
    }

    @Override
    public <T> T getOption(SocketOption<T> name) throws IOException {
        return delegate.getOption(name);
    }

    @Override
    public Set<SocketOption<?>> supportedOptions() {
        return delegate.supportedOptions();
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        return delegate.read(dsts, offset, length);
    }

    @Override
    public long read(ByteBuffer[] dsts) throws IOException {
        return delegate.read(dsts);
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        return delegate.read(dst);
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        return delegate.write(src);
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
