package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Result holds information about a discovered domain.
type Result struct {
	Domain     string   `json:"domain"`
	IPs        []string `json:"ips"`
	Registrant string   `json:"registrant"`
	Server     string   `json:"server"`
}

// Task defines a candidate domain lookup task.
type Task struct {
	baseName     string
	original     string
	candidateTLD string
}

// tldSlice contains the list of TLDs (you can update or replace this list as needed).
var tldSlice = []string{
	"aaa", "aarp", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi",
	"ac", "academy", "accenture", "accountant", "accountants", "aco", "actor",
	"ad", "ads", "adult", "ae", "aeg", "aero", "aetna", "af", "afl", "africa",
	"ag", "agakhan", "agency", "ai", "aig", "airbus", "airforce", "airtel", "akdn",
	"al", "alibaba", "alipay", "allfinanz", "allstate", "ally", "alsace", "alstom",
	"am", "amazon", "americanexpress", "americanfamily", "amex", "amfam", "amica",
	"amsterdam", "analytics", "android", "anquan", "anz", "ao", "aol",
	"apartments", "app", "apple", "aq", "aquarelle", "ar", "arab", "aramco",
	"archi", "army", "arpa", "art", "arte", "as", "asda", "asia", "associates",
	"at", "athleta", "attorney", "au", "auction", "audi", "audible", "audio",
	"auspost", "author", "auto", "autos", "aw", "aws", "ax", "axa", "az", "azure",
	"ba", "baby", "baidu", "banamex", "band", "bank", "bar", "barcelona",
	"barclaycard", "barclays", "barefoot", "bargains", "baseball", "basketball",
	"bauhaus", "bayern", "bb", "bbc", "bbt", "bbva", "bcg", "bcn", "bd", "be",
	"beats", "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bf",
	"bg", "bh", "bharti", "bi", "bible", "bid", "bike", "bing", "bingo", "bio",
	"biz", "bj", "black", "blackfriday", "blockbuster", "blog", "bloomberg",
	"blue", "bm", "bms", "bmw", "bn", "bnpparibas", "bo", "boats", "boehringer",
	"bofa", "bom", "bond", "boo", "book", "booking", "bosch", "bostik", "boston",
	"bot", "boutique", "box", "br", "bradesco", "bridgestone", "broadway",
	"broker", "brother", "brussels", "bs", "bt", "build", "builders", "business",
	"buy", "buzz", "bv", "bw", "by", "bz", "bzh", "ca", "cab", "cafe", "cal",
	"call", "calvinklein", "cam", "camera", "camp", "canon", "capetown", "capital",
	"capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars",
	"casa", "case", "cash", "casino", "cat", "catering", "catholic", "cba", "cbn",
	"cbre", "cc", "cd", "center", "ceo", "cern", "cf", "cfa", "cfd", "cg", "ch",
	"chanel", "channel", "charity", "chase", "chat", "cheap", "chintai",
	"christmas", "chrome", "church", "ci", "cipriani", "circle", "cisco",
	"citadel", "citi", "citic", "city", "ck", "cl", "claims", "cleaning", "click",
	"clinic", "clinique", "clothing", "cloud", "club", "clubmed", "cm", "cn", "co",
	"coach", "codes", "coffee", "college", "cologne", "com", "commbank",
	"community", "company", "compare", "computer", "comsec", "condos",
	"construction", "consulting", "contact", "contractors", "cooking", "cool",
	"coop", "corsica", "country", "coupon", "coupons", "courses", "cpa", "cr",
	"credit", "creditcard", "creditunion", "cricket", "crown", "crs", "cruise",
	"cruises", "cu", "cuisinella", "cv", "cw", "cx", "cy", "cymru", "cyou", "cz",
	"dad", "dance", "data", "date", "dating", "datsun", "day", "dclk", "dds", "de",
	"deal", "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta",
	"democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds",
	"diet", "digital", "direct", "directory", "discount", "discover", "dish",
	"diy", "dj", "dk", "dm", "dnp", "do", "docs", "doctor", "dog", "domains",
	"dot", "download", "drive", "dtv", "dubai", "dunlop", "dupont", "durban",
	"dvag", "dvr", "dz", "earth", "eat", "ec", "eco", "edeka", "edu", "education",
	"ee", "eg", "email", "emerck", "energy", "engineer", "engineering",
	"enterprises", "epson", "equipment", "er", "ericsson", "erni", "es", "esq",
	"estate", "et", "eu", "eurovision", "eus", "events", "exchange", "expert",
	"exposed", "express", "extraspace", "fage", "fail", "fairwinds", "faith",
	"family", "fan", "fans", "farm", "farmers", "fashion", "fast", "fedex",
	"feedback", "ferrari", "ferrero", "fi", "fidelity", "fido", "film", "final",
	"finance", "financial", "fire", "firestone", "firmdale", "fish", "fishing",
	"fit", "fitness", "fj", "fk", "flickr", "flights", "flir", "florist",
	"flowers", "fly", "fm", "fo", "foo", "food", "football", "ford", "forex",
	"forsale", "forum", "foundation", "fox", "fr", "free", "fresenius", "frl",
	"frogans", "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol",
	"fyi", "ga", "gal", "gallery", "gallo", "gallup", "game", "games", "gap",
	"garden", "gay", "gb", "gbiz", "gd", "gdn", "ge", "gea", "gent", "genting",
	"george", "gf", "gg", "ggee", "gh", "gi", "gift", "gifts", "gives", "giving",
	"gl", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh", "gmo", "gmx",
	"gn", "godaddy", "gold", "goldpoint", "golf", "goo", "goodyear", "goog",
	"google", "gop", "got", "gov", "gp", "gq", "gr", "grainger", "graphics",
	"gratis", "green", "gripe", "grocery", "group", "gs", "gt", "gu", "gucci",
	"guge", "guide", "guitars", "guru", "gw", "gy", "hair", "hamburg", "hangout",
	"haus", "hbo", "hdfc", "hdfcbank", "health", "healthcare", "help", "helsinki",
	"here", "hermes", "hiphop", "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm",
	"hn", "hockey", "holdings", "holiday", "homedepot", "homegoods", "homes",
	"homesense", "honda", "horse", "hospital", "host", "hosting", "hot", "hotels",
	"hotmail", "house", "how", "hr", "hsbc", "ht", "hu", "hughes", "hyatt",
	"hyundai", "ibm", "icbc", "ice", "icu", "id", "ie", "ieee", "ifm", "ikano",
	"il", "im", "imamat", "imdb", "immo", "immobilien", "in", "inc", "industries",
	"infiniti", "info", "ing", "ink", "institute", "insurance", "insure", "int",
	"international", "intuit", "investments", "io", "ipiranga", "iq", "ir",
	"irish", "is", "ismaili", "ist", "istanbul", "it", "itau", "itv", "jaguar",
	"java", "jcb", "je", "jeep", "jetzt", "jewelry", "jio", "jll", "jm", "jmp",
	"jnj", "jo", "jobs", "joburg", "jot", "joy", "jp", "jpmorgan", "jprs",
	"juegos", "juniper", "kaufen", "kddi", "ke", "kerryhotels", "kerrylogistics",
	"kerryproperties", "kfh", "kg", "kh", "ki", "kia", "kids", "kim", "kindle",
	"kitchen", "kiwi", "km", "kn", "koeln", "komatsu", "kosher", "kp", "kpmg",
	"kpn", "kr", "krd", "kred", "kuokgroup", "kw", "ky", "kyoto", "kz", "la",
	"lacaixa", "lamborghini", "lamer", "lancaster", "land", "landrover", "lanxess",
	"lasalle", "lat", "latino", "latrobe", "law", "lawyer", "lb", "lc", "lds",
	"lease", "leclerc", "lefrak", "legal", "lego", "lexus", "lgbt", "li", "lidl",
	"life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited",
	"limo", "lincoln", "link", "lipsy", "live", "living", "lk", "llc", "llp",
	"loan", "loans", "locker", "locus", "lol", "london", "lotte", "lotto", "love",
	"lpl", "lplfinancial", "lr", "ls", "lt", "ltd", "ltda", "lu", "lundbeck",
	"luxe", "luxury", "lv", "ly", "ma", "madrid", "maif", "maison", "makeup",
	"man", "management", "mango", "map", "market", "marketing", "markets",
	"marriott", "marshalls", "mattel", "mba", "mc", "mckinsey", "md", "me", "med",
	"media", "meet", "melbourne", "meme", "memorial", "men", "menu", "merckmsd",
	"mg", "mh", "miami", "microsoft", "mil", "mini", "mint", "mit", "mitsubishi",
	"mk", "ml", "mlb", "mls", "mm", "mma", "mn", "mo", "mobi", "mobile", "moda",
	"moe", "moi", "mom", "monash", "money", "monster", "mormon", "mortgage",
	"moscow", "moto", "motorcycles", "mov", "movie", "mp", "mq", "mr", "ms", "msd",
	"mt", "mtn", "mtr", "mu", "museum", "music", "mv", "mw", "mx", "my", "mz",
	"na", "nab", "nagoya", "name", "navy", "nba", "nc", "ne", "nec", "net",
	"netbank", "netflix", "network", "neustar", "new", "news", "next",
	"nextdirect", "nexus", "nf", "nfl", "ng", "ngo", "nhk", "ni", "nico", "nike",
	"nikon", "ninja", "nissan", "nissay", "nl", "no", "nokia", "norton", "now",
	"nowruz", "nowtv", "np", "nr", "nra", "nrw", "ntt", "nu", "nyc", "nz", "obi",
	"observer", "office", "okinawa", "olayan", "olayangroup", "ollo", "om",
	"omega", "one", "ong", "onl", "online", "ooo", "open", "oracle", "orange",
	"org", "organic", "origins", "osaka", "otsuka", "ott", "ovh", "pa", "page",
	"panasonic", "paris", "pars", "partners", "parts", "party", "pay", "pccw",
	"pe", "pet", "pf", "pfizer", "pg", "ph", "pharmacy", "phd", "philips", "phone",
	"photo", "photography", "photos", "physio", "pics", "pictet", "pictures",
	"pid", "pin", "ping", "pink", "pioneer", "pizza", "pk", "pl", "place", "play",
	"playstation", "plumbing", "plus", "pm", "pn", "pnc", "pohl", "poker",
	"politie", "porn", "post", "pr", "pramerica", "praxi", "press", "prime", "pro",
	"prod", "productions", "prof", "progressive", "promo", "properties",
	"property", "protection", "pru", "prudential", "ps", "pt", "pub", "pw", "pwc",
	"py", "qa", "qpon", "quebec", "quest", "racing", "radio", "re", "read",
	"realestate", "realtor", "realty", "recipes", "red", "redstone", "redumbrella",
	"rehab", "reise", "reisen", "reit", "reliance", "ren", "rent", "rentals",
	"repair", "report", "republican", "rest", "restaurant", "review", "reviews",
	"rexroth", "rich", "richardli", "ricoh", "ril", "rio", "rip", "ro", "rocks",
	"rodeo", "rogers", "room", "rs", "rsvp", "ru", "rugby", "ruhr", "run", "rw",
	"rwe", "ryukyu", "sa", "saarland", "safe", "safety", "sakura", "sale", "salon",
	"samsclub", "samsung", "sandvik", "sandvikcoromant", "sanofi", "sap", "sarl",
	"sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "scb", "schaeffler",
	"schmidt", "scholarships", "school", "schule", "schwarz", "science", "scot",
	"sd", "se", "search", "seat", "secure", "security", "seek", "select", "sener",
	"services", "seven", "sew", "sex", "sexy", "sfr", "sg", "sh", "shangrila",
	"sharp", "shell", "shia", "shiksha", "shoes", "shop", "shopping", "shouji",
	"show", "si", "silk", "sina", "singles", "site", "sj", "sk", "ski", "skin",
	"sky", "skype", "sl", "sling", "sm", "smart", "smile", "sn", "sncf", "so",
	"soccer", "social", "softbank", "software", "sohu", "solar", "solutions",
	"song", "sony", "soy", "spa", "space", "sport", "spot", "sr", "srl", "ss",
	"st", "stada", "staples", "star", "statebank", "statefarm", "stc", "stcgroup",
	"stockholm", "storage", "store", "stream", "studio", "study", "style", "su",
	"sucks", "supplies", "supply", "support", "surf", "surgery", "suzuki", "sv",
	"swatch", "swiss", "sx", "sy", "sydney", "systems", "sz", "tab", "taipei",
	"talk", "taobao", "target", "tatamotors", "tatar", "tattoo", "tax", "taxi",
	"tc", "tci", "td", "tdk", "team", "tech", "technology", "tel", "temasek",
	"tennis", "teva", "tf", "tg", "th", "thd", "theater", "theatre", "tiaa",
	"tickets", "tienda", "tips", "tires", "tirol", "tj", "tjmaxx", "tjx", "tk",
	"tkmaxx", "tl", "tm", "tmall", "tn", "to", "today", "tokyo", "tools", "top",
	"toray", "toshiba", "total", "tours", "town", "toyota", "toys", "tr", "trade",
	"trading", "training", "travel", "travelers", "travelersinsurance", "trust",
	"trv", "tt", "tube", "tui", "tunes", "tushu", "tv", "tvs", "tw", "tz", "ua",
	"ubank", "ubs", "ug", "uk", "unicom", "university", "uno", "uol", "ups", "us",
	"uy", "uz", "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas",
	"ventures", "verisign", "versicherung", "vet", "vg", "vi", "viajes", "video",
	"vig", "viking", "villas", "vin", "vip", "virgin", "visa", "vision", "viva",
	"vivo", "vlaanderen", "vn", "vodka", "volvo", "vote", "voting", "voto",
	"voyage", "vu", "wales", "walmart", "walter", "wang", "wanggou", "watch",
	"watches", "weather", "weatherchannel", "webcam", "weber", "website", "wed",
	"wedding", "weibo", "weir", "wf", "whoswho", "wien", "wiki", "williamhill",
	"win", "windows", "wine", "winners", "wme", "wolterskluwer", "woodside",
	"work", "works", "world", "wow", "ws", "wtc", "wtf", "xbox", "xerox", "xihuan",
	"xin", "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a", "xn--2scrj9c",
	"xn--30rr7y", "xn--3bst00m", "xn--3ds443g", "xn--3e0b707e", "xn--3hcrj9c",
	"xn--3pxu8k", "xn--42c2d9a", "xn--45br5cyl", "xn--45brj9c", "xn--45q11c",
	"xn--4dbrk0ce", "xn--4gbrim", "xn--54b7fta0cc", "xn--55qw42g", "xn--55qx5d",
	"xn--5su34j936bgsg", "xn--5tzm5g", "xn--6frz82g", "xn--6qq986b3xl",
	"xn--80adxhks", "xn--80ao21a", "xn--80aqecdr1a", "xn--80asehdb", "xn--80aswg",
	"xn--8y0a063a", "xn--90a3ac", "xn--90ae", "xn--90ais", "xn--9dbq2a",
	"xn--9et52u", "xn--9krt00a", "xn--b4w605ferd", "xn--bck1b9a5dre4c",
	"xn--c1avg", "xn--c2br7g", "xn--cck2b3b", "xn--cckwcxetd", "xn--cg4bki",
	"xn--clchc0ea0b2g2a9gcd", "xn--czr694b", "xn--czrs0t", "xn--czru2d",
	"xn--d1acj3b", "xn--d1alf", "xn--e1a4c", "xn--eckvdtc9d", "xn--efvy88h",
	"xn--fct429k", "xn--fhbei", "xn--fiq228c5hs", "xn--fiq64b", "xn--fiqs8s",
	"xn--fiqz9s", "xn--fjq720a", "xn--flw351e", "xn--fpcrj9c3d", "xn--fzc2c9e2c",
	"xn--fzys8d69uvgm", "xn--g2xx48c", "xn--gckr3f0f", "xn--gecrj9c",
	"xn--gk3at1e", "xn--h2breg3eve", "xn--h2brj9c", "xn--h2brj9c8c", "xn--hxt814e",
	"xn--i1b6b1a6a2e", "xn--imr513n", "xn--io0a7i", "xn--j1aef", "xn--j1amh",
	"xn--j6w193g", "xn--jlq480n2rg", "xn--jvr189m", "xn--kcrx77d1x4a",
	"xn--kprw13d", "xn--kpry57d", "xn--kput3i", "xn--l1acc", "xn--lgbbat1ad8j",
	"xn--mgb9awbf", "xn--mgba3a3ejt", "xn--mgba3a4f16a", "xn--mgba7c0bbn0a",
	"xn--mgbaam7a8h", "xn--mgbab2bd", "xn--mgbah1a3hjkrd", "xn--mgbai9azgqp6j",
	"xn--mgbayh7gpa", "xn--mgbbh1a", "xn--mgbbh1a71e", "xn--mgbc0a9azcg",
	"xn--mgbca7dzdo", "xn--mgbcpq6gpa1a", "xn--mgberp4a5d4ar", "xn--mgbgu82a",
	"xn--mgbi4ecexp", "xn--mgbpl2fh", "xn--mgbt3dhd", "xn--mgbtx2b",
	"xn--mgbx4cd0ab", "xn--mix891f", "xn--mk1bu44c", "xn--mxtq1m", "xn--ngbc5azd",
	"xn--ngbe9e0a", "xn--ngbrx", "xn--node", "xn--nqv7f", "xn--nqv7fs00ema",
	"xn--nyqy26a", "xn--o3cw4h", "xn--ogbpf8fl", "xn--otu796d", "xn--p1acf",
	"xn--p1ai", "xn--pgbs0dh", "xn--pssy2u", "xn--q7ce6a", "xn--q9jyb4c",
	"xn--qcka1pmc", "xn--qxa6a", "xn--qxam", "xn--rhqv96g", "xn--rovu88b",
	"xn--rvc1e0am3e", "xn--s9brj9c", "xn--ses554g", "xn--t60b56a", "xn--tckwe",
	"xn--tiq49xqyj", "xn--unup4y", "xn--vermgensberater-ctb",
	"xn--vermgensberatung-pwb", "xn--vhquv", "xn--vuq861b", "xn--w4r85el8fhu5dnra",
	"xn--w4rs40l", "xn--wgbh1c", "xn--wgbl6a", "xn--xhq521b", "xn--xkc2al3hye2a",
	"xn--xkc2dl3a5ee0h", "xn--y9a3aq", "xn--yfro4i67o", "xn--ygbi2ammx",
	"xn--zfr164b", "xxx", "xyz", "yachts", "yahoo", "yamaxun", "yandex", "ye",
	"yodobashi", "yoga", "yokohama", "you", "youtube", "yt", "yun", "za", "zappos",
	"zara", "zero", "zip", "zm", "zone", "zuerich", "zw",
}

// tldMap is a map for fast TLD lookups.
var tldMap map[string]struct{}

// initTLDMap initializes the TLD lookup map.
func initTLDMap() {
	tldMap = make(map[string]struct{}, len(tldSlice))
	for _, tld := range tldSlice {
		tldLower := strings.ToLower(tld)
		tldMap[tldLower] = struct{}{}
	}
}

func main() {
	// Define command-line flags.
	domain := flag.String("d", "", "Domain to test against (single target)")
	domainList := flag.String("dL", "", "List of targets (e.g., targets.txt)")
	silent := flag.Bool("s", false, "Silent output")
	verbose := flag.Bool("v", false, "Verbose output")
	outputFile := flag.String("o", "", "Output file (json or txt)")
	debug := flag.Bool("debug", false, "Debugging mode")
	flag.Parse()

	if !*silent {
		printBanner()
	}

	// Validate input.
	if (*domain == "" && *domainList == "") || (*domain != "" && *domainList != "") {
		fmt.Println("Please specify either -d or -dL, but not both.")
		os.Exit(1)
	}

	// Load domains to test.
	var domains []string
	if *domain != "" {
		domains = append(domains, *domain)
	} else {
		file, err := os.Open(*domainList)
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				domains = append(domains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file: %v", err)
		}
	}

	// Initialize TLD map.
	initTLDMap()

	var results []Result
	var resMutex sync.Mutex

	// Create a worker pool for concurrent TLD enumeration.
	const workerCount = 20
	tasks := make(chan Task)
	var wg sync.WaitGroup

	// Launch worker goroutines.
	for i := 0; i < workerCount; i++ {
		go func() {
			for task := range tasks {
				processTask(task, *silent, *verbose, *debug, &results, &resMutex)
				wg.Done()
			}
		}()
	}

	// Process each input domain.
	for _, domainName := range domains {
		baseName, originalTLD := extractBaseName(domainName)
		if baseName == "" {
			if *debug {
				log.Printf("Could not extract base name from domain: %s", domainName)
			}
			continue
		}
		if *debug {
			log.Printf("Base name: %s, Original TLD: %s", baseName, originalTLD)
		}

		// Check if the original domain exists.
		if exists, _ := checkDomain(domainName); !exists {
			if *debug {
				log.Printf("Domain %s does not exist.", domainName)
			}
			continue
		}

		// For each TLD in the list, create a task (skip the original TLD).
		for _, tld := range tldSlice {
			candidateDomain := baseName + "." + strings.ToLower(tld)
			if candidateDomain == domainName {
				continue
			}
			wg.Add(1)
			tasks <- Task{
				baseName:     baseName,
				original:     domainName,
				candidateTLD: strings.ToLower(tld),
			}
		}
	}

	wg.Wait()
	close(tasks)

	// Output results.
	if !*silent {
		for _, result := range results {
			fmt.Printf("\033[31mDomain: %s\033[0m\n", result.Domain)
			fmt.Printf("IPs: %v\n", result.IPs)
			fmt.Printf("Registrant: %s\n", result.Registrant)
			fmt.Printf("Server: %s\n\n", result.Server)
		}
	}
	if *outputFile != "" {
		if err := outputResults(results, *outputFile); err != nil {
			log.Printf("Error writing output: %v", err)
		}
	}
}

// processTask performs DNS and WHOIS lookups for a candidate domain.
func processTask(task Task, silent bool, verbose bool, debug bool, results *[]Result, resMutex *sync.Mutex) {
	candidateDomain := task.baseName + "." + task.candidateTLD
	if exists, ips := checkDomain(candidateDomain); exists {
		registrant, server := performWhois(candidateDomain, debug)
		res := Result{
			Domain:     candidateDomain,
			IPs:        ips,
			Registrant: registrant,
			Server:     server,
		}
		resMutex.Lock()
		*results = append(*results, res)
		resMutex.Unlock()

		if !silent {
			fmt.Printf("\033[31mDomain: %s\033[0m\n", candidateDomain)
			fmt.Printf("IPs: %v\n", ips)
			fmt.Printf("Registrant: %s\n", registrant)
			fmt.Printf("Server: %s\n\n", server)
		}
	} else if verbose {
		log.Printf("Domain %s does not exist.", candidateDomain)
	}
}

// printBanner displays the tool banner.
func printBanner() {
	cyan := "\033[36m"
	reset := "\033[0m"
	banner := `
 ========================================
   TLDBuster by r3dcl1ff @Redflare-Cyber
 ========================================
`
	fmt.Printf("%s%s%s\n", cyan, banner, reset)
}

// extractBaseName returns the base name and TLD from a given domain.
func extractBaseName(domain string) (string, string) {
	domain = strings.ToLower(domain)
	labels := strings.Split(domain, ".")
	// Iterate from the rightmost label backward.
	for i := 1; i <= len(labels); i++ {
		possibleTLD := strings.Join(labels[len(labels)-i:], ".")
		if _, ok := tldMap[possibleTLD]; ok {
			baseName := strings.Join(labels[:len(labels)-i], ".")
			return baseName, possibleTLD
		}
	}
	return "", ""
}

// checkDomain uses a context with timeout to resolve the domain.
func checkDomain(domain string) (bool, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return false, nil
	}
	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.IP.String())
	}
	return true, ipStrs
}

// performWhois queries the WHOIS server and extracts registrant and registrar details.
func performWhois(domain string, debug bool) (string, string) {
	tld := getTLD(domain)
	// Using a simple mapping; you can extend this for TLDs with different WHOIS servers.
	whoisServer := "whois.nic." + tld

	conn, err := net.DialTimeout("tcp", whoisServer+":43", 5*time.Second)
	if err != nil {
		if debug {
			log.Printf("Error connecting to WHOIS server for %s: %v", domain, err)
		}
		return "", ""
	}
	defer conn.Close()

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		if debug {
			log.Printf("Error writing to WHOIS server for %s: %v", domain, err)
		}
		return "", ""
	}

	var resultBuilder strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		resultBuilder.WriteString(scanner.Text() + "\n")
	}
	if err := scanner.Err(); err != nil && debug {
		log.Printf("Error reading WHOIS response for %s: %v", domain, err)
	}
	response := resultBuilder.String()

	// Use regex with case-insensitive matching to extract fields.
	registrant := extractField(response, `(?i)Registrant Name:\s*(.*)`)
	if registrant == "" {
		registrant = extractField(response, `(?i)Admin Name:\s*(.*)`)
	}
	server := extractField(response, `(?i)Registrar:\s*(.*)`)

	return registrant, server
}

// getTLD extracts the TLD from a domain.
func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// extractField uses regex to extract a field from WHOIS data.
func extractField(data, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(data)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

// outputResults writes the results to a file in JSON or plain text format.
func outputResults(results []Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if strings.HasSuffix(strings.ToLower(filename), ".json") {
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}

	// TXT format.
	for _, result := range results {
		file.WriteString(fmt.Sprintf("Domain: %s\n", result.Domain))
		file.WriteString(fmt.Sprintf("IPs: %v\n", result.IPs))
		file.WriteString(fmt.Sprintf("Registrant: %s\n", result.Registrant))
		file.WriteString(fmt.Sprintf("Server: %s\n\n", result.Server))
	}
	return nil
}
