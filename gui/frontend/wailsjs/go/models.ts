export namespace main {
	
	export class DumpParams {
	    package: string;
	    suCmd: string;
	    outputDir: string;
	    adbPath: string;
	    hostPort: string;
	    mode: string;
	    restart: boolean;
	    watch: boolean;
	    dryLimit: number;
	    maxSeconds: number;
	    maxRounds: number;
	    stealth: boolean;
	    stealth2: boolean;
	    relaxed: boolean;
	    anon: boolean;
	    regionDelayMs: number;
	
	    static createFrom(source: any = {}) {
	        return new DumpParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.package = source["package"];
	        this.suCmd = source["suCmd"];
	        this.outputDir = source["outputDir"];
	        this.adbPath = source["adbPath"];
	        this.hostPort = source["hostPort"];
	        this.mode = source["mode"];
	        this.restart = source["restart"];
	        this.watch = source["watch"];
	        this.dryLimit = source["dryLimit"];
	        this.maxSeconds = source["maxSeconds"];
	        this.maxRounds = source["maxRounds"];
	        this.stealth = source["stealth"];
	        this.stealth2 = source["stealth2"];
	        this.relaxed = source["relaxed"];
	        this.anon = source["anon"];
	        this.regionDelayMs = source["regionDelayMs"];
	    }
	}
	export class DumpResult {
	    success: boolean;
	    message: string;
	    dexCount: number;
	    soCount: number;
	    fixedCount: number;
	    totalSize: number;
	    outputDir: string;
	    rounds: number;
	    processes: number;
	
	    static createFrom(source: any = {}) {
	        return new DumpResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.message = source["message"];
	        this.dexCount = source["dexCount"];
	        this.soCount = source["soCount"];
	        this.fixedCount = source["fixedCount"];
	        this.totalSize = source["totalSize"];
	        this.outputDir = source["outputDir"];
	        this.rounds = source["rounds"];
	        this.processes = source["processes"];
	    }
	}
	export class GetAppListResult {
	    packages: string[];
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new GetAppListResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packages = source["packages"];
	        this.error = source["error"];
	    }
	}

}

