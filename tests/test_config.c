#define NOMAIN
#include "../serve.c"

typedef struct {
	string src;
	ConfigEntry *entries;
	int count;
} Test;

int main(void)
{
	Test tests[] = {
		{
			.src = LIT(""),
			.count = 0,
		},
		{
			.src = LIT("  \r   \n  "),
			.count = 0,
		},
		{
			.src = LIT("# Comment"),
			.count = 0,
		},
		{
			.src = LIT("# Comment\n"),
			.count = 0,
		},
		{
			.src = LIT("  \r   \n  # Comment"),
			.count = 0,
		},
		{
			// Invalid charactere where a name was expected
			.src = LIT("@"),
			.count = -1,
		},
		{
			// Invalid charactere where a name was expected
			.src = LIT(" \r\n @"),
			.count = -1,
		},
		{
			// Valid field name but missing value
			.src = LIT("xxx"),
			.count = -1,
		},
		{
			// Valid field name but missing value (with spaces after the name)
			.src = LIT("xxx \r "),
			.count = -1,
		},
		{
			// Test various string and bool entries
			.src = LIT(
				"a y\n"
				"b ye\n"
				"c yes\n"
				"d yesx\n"
				"e n\n"
				"f no\n"
				"g nox\n"
				"h \"\"\n"
				"i \"hello world!\"\n"
			),
			.count = 9,
			.entries = (ConfigEntry[]) {
				{.name=LIT("a"), .type=CE_STR,  .txt=LIT("y")},
				{.name=LIT("b"), .type=CE_STR,  .txt=LIT("ye")},
				{.name=LIT("c"), .type=CE_BOOL, .yes=true},
				{.name=LIT("d"), .type=CE_STR,  .txt=LIT("yesx")},
				{.name=LIT("e"), .type=CE_STR,  .txt=LIT("n")},
				{.name=LIT("f"), .type=CE_BOOL, .yes=false},
				{.name=LIT("g"), .type=CE_STR,  .txt=LIT("nox")},
				{.name=LIT("h"), .type=CE_STR,  .txt=LIT("")},
				{.name=LIT("i"), .type=CE_STR,  .txt=LIT("hello world!")},
			},
		},
		{
			// Test various integer entries
			.src = LIT(
				"a 0\n"
				"b 1000\n"
				"c 4294967295\n" // Maximum value
			),
			.count = 3,
			.entries = (ConfigEntry[]) {
				{.name=LIT("a"), .type=CE_INT, .num=0},
				{.name=LIT("b"), .type=CE_INT, .num=1000},
				{.name=LIT("c"), .type=CE_INT, .num=-1},
			},
		},
		{
			// Test overflow
			.src = LIT(
				"a 4294967296\n" // Maximum value plus 1
			),
			.count = -1,
		},
		{
			// Test valid field names
			.src = LIT(
				"_  0\n"
				"_a 0\n"
				"a0 0\n"
			),
			.count = 3,
			.entries = (ConfigEntry[]) {
				{.name=LIT("_"),  .type=CE_INT, .num=0},
				{.name=LIT("_a"), .type=CE_INT, .num=0},
				{.name=LIT("a0"), .type=CE_INT, .num=0},
			},
		},
		{
			// Test invalid name starting with a digit
			.src = LIT(
				"0"
			),
			.count = -1,
		},
		{
			// Test invalid name starting with an unprintable character
			.src = LIT(
				"\xff"
			),
			.count = -1,
		},
		{
			// Test comments
			.src = LIT(
				"# comment\n"
				"field 0 # comment\n"
				"\n"
				"# comment\n"
			),
			.count = 1,
			.entries = (ConfigEntry[]) {
				{.name=LIT("field"), .type=CE_INT, .num=0},
			},
		},
		{
			// Test invalid character after field
			.src = LIT(
				"field 0 ;"
			),
			.count = -1,
		}
	};

	int total  = 0;
	int passed = 0;
	for (int i = 0; i < COUNTOF(tests); i++) {
		config_init();
		bool ok = config_parse(tests[i].src);
		if (tests[i].count == -1) {
			if (ok) {
				// Parsing succeded but was expected a failure
				printf("Test %d: Parsing succeded but was expected a failure\n", i);
			} else {
				printf("Test %d: Passed\n", i);
				passed++;
			}
		} else {
			assert(tests[i].count > -1);
			if (ok) {
				bool match = true;
				for (int j = 0; j < config_count; j++) {

					match = false;
					bool found = false;
					ConfigEntry entry = config_entries[j];

					for (int k = 0; k < tests[i].count; k++) {

						ConfigEntry expect = tests[i].entries[k];

						if (streq(entry.name, expect.name)) {

							found = true;

							if (entry.type != expect.type) {
								printf("Entry '%.*s' has the wrong type\n",
									(int) entry.name.size, entry.name.data);
								break;
							}

							switch (entry.type) {
								case CE_BOOL: match = (entry.yes == expect.yes); break;
								case CE_INT: match = (entry.num == expect.num); break;
								case CE_STR: match = streq(entry.txt, expect.txt); break;
							}

							if (match)
								break;

							printf("Entry '%.*s' has the wrong value\n",
								(int) entry.name.size, entry.name.data);
						}
					}

					if (!match) {
						if (!found)
							printf("Entry '%.*s' is missing\n",
								(int) entry.name.size, entry.name.data);
						break;
					}
				}
				if (match) {
					printf("Test %d: Passed\n", i);
					passed++;
				} else {
					printf("Test %d: Failed\n", i);
				}
			} else {
				printf("Test %d: Parsing failed but was expected to succede\n", i);
			}
		}
		config_free();
		total++;
	}
	printf("Passed %d/%d\n", passed, total);
	return (passed == total) ? 0 : -1;
}
