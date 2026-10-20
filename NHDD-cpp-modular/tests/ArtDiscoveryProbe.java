import dalvik.system.DexFile;

// Own-process ART fixture; no instrumentation of third-party applications.
public class ArtDiscoveryProbe {
    private static DexFile retained;
    private static native long eraseHeader(String path);
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("payload.dex helper.so erase|normal");
        retained = new DexFile(args[0]);
        System.load(args[1]);
        long address = args[2].equals("erase") ? eraseHeader(args[0]) : 0;
        if (args[2].equals("erase") && address == 0) throw new IllegalStateException("no private DEX mapping");
        System.out.println("ART_PROBE pid=" + android.os.Process.myPid() + " erased_bytes=" +
                (address == 0 ? 0 : 44) + " payload_address=0x" + Long.toHexString(address));
        System.out.flush();
        Thread.sleep(90000);
        retained.close();
    }
}
