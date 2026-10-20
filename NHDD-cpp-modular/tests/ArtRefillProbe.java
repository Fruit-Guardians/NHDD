import dalvik.system.DexFile;

// Controlled own-process fixture. Never executes the deliberately altered payload.
public class ArtRefillProbe {
    private static DexFile retained;
    private static native String prepare(String path, String prefix, String mode);
    private static native void windows(String prefix, String mode);
    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("payload.dex helper.so prefix mode");
        retained = new DexFile(args[0]);
        System.load(args[1]);
        System.out.println("READY " + prepare(args[0], args[2], args[3]));
        System.out.flush();
        windows(args[2], args[3]);
        retained.close();
    }
}
