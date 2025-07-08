package com.mayreh.jktls;

import com.mayreh.jktls.sun.nio.ch.FileChannelImpl;
import com.mayreh.jktls.sun.nio.ch.SocketChannelImpl;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
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

    private static native void setTcpUlp(int fd, String name);

    private static final int SOL_TCP = 6;
    private static final int SOL_TLS = 282;
    private static final int TCP_ULP = 31;
    private static final int TLS_TX = 1;

    private static void setTcpUlp2(int fd, String name) {
        try (Arena arena = Arena.ofConfined()) {
            var mem = arena.allocateFrom(name);
            int ret = (int) methodHandle.invoke(fd,
                    SOL_TCP,
                    TCP_ULP,
                    mem.address(),
                    Math.toIntExact(mem.byteSize()));
            if (ret != 0) {
                throw new RuntimeException("Onoz got " + ret);
            }
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private static native void setTlsTx(
            int fd, String protocol, String cipherSuite, byte[] iv, byte[] key, byte[] salt, byte[] recSeq);

    private static native void setTlsTx2(
            int fd, String protocol, String cipherSuite, byte[] iv, byte[] key, byte[] salt, byte[] recSeq
    ) {
        try (Arena arena = Arena.ofConfined()) {
            var mem = arena.allocateFrom(cipherSuite);
            int ret = (int) methodHandle.invoke(fd,
                    SOL_TCP,
                    TCP_ULP,
                    mem.address(),
                    Math.toIntExact(mem.byteSize()));
            if (ret != 0) {
                throw new RuntimeException("Onoz got " + ret);
            }
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private static native long sendFile(int outFd, int inFd, long position, long count);

    private final SocketChannel delegate;
    private final SocketChannelImpl impl;

    public static KTlsSocketChannel wrap(SocketChannel channel) {
        if (!SocketChannelImpl.isInstance(channel)) {
            throw new UnsupportedOperationException("Unsupported SocketChannel implementation");
        }
        return new KTlsSocketChannel(channel, new SocketChannelImpl(channel));
    }

    private static final Linker nativeLinker = Linker.nativeLinker();
    private static final SymbolLookup stdlibLookup = nativeLinker.defaultLookup();
    private static final SymbolLookup loaderLookup = SymbolLookup.loaderLookup();
    private static final FunctionDescriptor setsockoptDescriptor = FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);
    private static final String symbolName = "setsockopt";
    private static final MethodHandle methodHandle = loaderLookup.find(symbolName)
            .or(() -> stdlibLookup.find(symbolName))
            .map(symbolSegment -> nativeLinker.downcallHandle(symbolSegment, setsockoptDescriptor))
            .orElse(null);

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
            System.out.println("hek1");
            setTcpUlp(FDUtil.fdVal(impl.getFD()), (String) value);
            return this;
        }
        if (name == KTlsSocketOptions.TLS_TX) {
            System.out.println("hek2");
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
