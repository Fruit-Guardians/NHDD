import dalvik.system.DexClassLoader;
import java.io.File;

// Run only against this repository's own reconstructed test payload.
public class ArtRefillVerify {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("fixed.dex private-cache-dir markerNNN");
        new File(args[1]).mkdirs();
        DexClassLoader loader = new DexClassLoader(args[0], args[1], null, ArtRefillVerify.class.getClassLoader());
        Class<?> type = Class.forName("nhdd.fixture.ArtRefillPayload", true, loader);
        int result = (Integer) type.getMethod(args[2], int.class).invoke(null, 11);
        int expected = 11 * 7 + Integer.parseInt(args[2].substring(6)) + 19;
        if (result != expected) throw new AssertionError("result=" + result + " expected=" + expected);
        System.out.println("ART_VERIFY_PASS method=" + args[2] + " result=" + result + " expected=" + expected);
    }
}
