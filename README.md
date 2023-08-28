# yara-dedup


Reads a file full of Yara rules and deduplicates them based on:
- Same rule name
- Same set of Condition and Strings: This is often useful because people will often rip rules from everywhere and rename the rule. Also, I am explicitely ignoring the Yara meta variables because some threat intel vendors like to add "2023 Copyright" that is updated each year.

