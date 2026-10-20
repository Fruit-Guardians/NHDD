import dalvik.system.DexClassLoader;
import java.io.File;

// Run only against this repository's own reconstructed test payload.
public class ArtRefillVerify {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) throw new IllegalArgumentException("fixed.dex private-cache-dir markerNNN [markerNNN...]");
        new File(args[1]).mkdirs();
        DexClassLoader loader = new DexClassLoader(args[0], args[1], null, ArtRefillVerify.class.getClassLoader());
        Class<?> type = Class.forName("nhdd.fixture.ArtRefillPayload", true, loader);
        for (int i=2;i<args.length;++i) {
            int result = (Integer) type.getMethod(args[i], int.class).invoke(null, 11);
            int expected = 11 * 7 + Integer.parseInt(args[i].substring(6)) + 19;
            if (result != expected) throw new AssertionError("result=" + result + " expected=" + expected);
            System.out.println("ART_VERIFY_PASS method=" + args[i] + " result=" + result + " expected=" + expected);
        }
    }
}
