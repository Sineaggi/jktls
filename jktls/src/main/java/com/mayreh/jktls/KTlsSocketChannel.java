package com.mayreh.jktls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.net.SocketAddress;
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

/**
 * A wrapper around {@link SocketChannel} with some tweaks to utilize kernel TLS.
 */
public class KTlsSocketChannel implements ByteChannel,
                                          ScatteringByteChannel,
                                          GatheringByteChannel,
                                          NetworkChannel {
    static {
        NativeLoader.load();
    }

    KTlsSocketChannel(SocketChannel delegate, SocketChannelImpl impl) {
        this.delegate = delegate;
        this.impl = impl;
    }

    private static int SOL_TCP = 6;
    private static int SOL_TLS = 282;
    private static int TCP_ULP = 31;
    private static int TLS_TX = 1;

    private static final MethodHandle setsockoptHandle;
    private static final MethodHandle sendfile64Handle;
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
        sendfile64Handle = linker.downcallHandle(sendfile64Address, sendfile64Descriptor);
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
        setsockoptHandle = linker.downcallHandle(setsockoptAddress, setsockoptDescriptor);
    }

    private static void setTcpUlp(int fd, String name) {
        try (var arena = Arena.ofConfined()) {
            var n = arena.allocateFrom(name);
            setsockoptHandle.invoke(
                    fd,
                    SOL_TCP,
                    TCP_ULP,
                    n,
                    Math.toIntExact(n.byteSize())
            );
        } catch (Error | RuntimeException ex) {
            throw ex;
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static native void setTlsTx(
            int fd, String protocol, String cipherSuite, byte[] iv, byte[] key, byte[] salt, byte[] recSeq);

    private static long sendFile(int outFd, int inFd, long position, long count) {
        try {
            return (long) sendfile64Handle.invokeExact(outFd, inFd, MemorySegment.ofAddress(position), count);
        } catch (Error | RuntimeException ex) {
            throw ex;
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private final SocketChannel delegate;
    private final SocketChannelImpl impl;

    public static KTlsSocketChannel wrap(SocketChannel channel) {
        if (!SocketChannelImpl.isInstance(channel)) {
            throw new UnsupportedOperationException("Unsupported SocketChannel implementation");
        }
        return new KTlsSocketChannel(channel, new SocketChannelImpl(channel));
    }

    public long transferFrom(FileChannel channel, long position, long count) {
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
