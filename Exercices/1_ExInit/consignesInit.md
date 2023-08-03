# Intro

This formation looks at YARA, a malware analysis tool used to detect patterns of malware characteristics in files, using a rule-based approach. We will focus on what YARA is, how to install it in Windows and Linux environments, and finally handle its syntax.

### Table of contents
- [Intro](#intro)
    - [Table of contents](#table-of-contents)
    - [What is YARA?](#what-is-yara)
    - [YARA synthax rules](#yara-synthax-rules)
      - [Header](#header)
      - [Metadata](#metadata)
      - [Strings](#strings)
      - [Condition](#condition)
      - [Comments](#comments)
    - [Running YARA rules](#running-yara-rules)
      - [Your turn](#your-turn)

### What is YARA?
YARA is an open-source tool used for malware analysis. YARA uses a rule-based approach to match patterns of malware characteristics in files. The rules usually contain strings, regular expressions, and special operators that describe certain characteristics of malware families followed by a boolean operation.

### YARA synthax rules
Here is an exemple of a YARA rule:

```c
rule SectionSample{
  meta:
   author = “Descartes”
   description = “Simple YARA rule”
  strings:
    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
    $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
  
  condition:
   any of them //checks whether a file has any of the above rules //$a or $b or $c
}
```
The above rule is telling YARA that any file containing one of the three strings must be reported as silent_banker. This is just a simple example, more complex and powerful rules can be created by using [wild-cards](#wild-cards), [case-insensitive strings](#case-insensitive-strings), [regular expressions](#regular-expressions), [special operators](#special-operators) and many other features.

First let explain each section of the example.

#### Header

```c
rule SectionSample{
}
```

Every YARA rule has the keyword `rule` as seen in the first line of this rule. The keyword is then followed by a rule name or identifier, in our case, it’s `SectionSample`.

- The first character cannot be a digit, like in the C programming language. 
- All alphanumeric characters are allowed
- Yara keywords are not allowed : https://yara.readthedocs.io/en/v3.6.3/writingrules.html#id2 


#### Metadata

```c
  meta :
    created = "01/06/2023 00:00:00"
    modified = "09/07/2023 11:44:00"
    author = “Descartes”
    description = “Simple YARA rule”
```

This line contains the metadata of the YARA rule. 

They can be added to help identify the files that were picked up by a certain rule. The metadata identifiers are always followed by an equal sign and the set value. The assigned values can be strings, integers, or a Boolean value. Note that identifier/value pairs defined in the metadata section can’t be used in the condition section, their only purpose is to store additional information about the rule.

In this section, you can include the author's name, the date you created the rule, a description of what the rule does etc. 

#### Strings

```c
  strings:
    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
    $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
```


The `strings` section contains values we want to search for in files. This section can contain text, hexadecimal, or regular expressions. 
`$[variableName]` are the variables where we will store our strings. Here we have 3 variables : $a $b $c

#### Condition

```c
  condition:
   any of them //checks whether a file has any of the above rules
```
Conditions are boolean expressions that guide the YARA engine in matching the strings. This is the only section required to ceate a Yara rules. 

This section specifies when the rule result is true for the object (file) that is under investigation.
You can also include another rule as part of your conditions.

Here, our sample rule will check if a file has any of the two strings `a`, `b` and `c`. 

Conditions can also include the [location](#locationSearch) of a string in the file. This helps especially in identifying the file type and hence reducing the chances of our rules producing false positives.

We can also include file size as a condition when we want to know the approximate size of a malware file. Malware researchers do share the file size of malware files and we can use that to enhance our YARA rules.

#### Comments
YARA rules can also contain comments just like in other programming languages. To write comments in YARA, we use `//` for single-line comments and `/* */` for multi-line comments.

We save YARA rules as files with the extension `. yar`. A single `. yar` file can contain more than one YARA rule. 

### Running YARA rules

#### Your turn
- Open any code editor of your choice 
-  Copy our sample YARA rule and save the file as a `sample. yar` or any random name 
-  Create another text file and add `Readers` to it
-  Add some random text to the file and save it as a text file (`.txt`). 
-  Ouvrez un terminal de commande 
-  Go to the folder where your file and yaraRules are 
-  Enter `yara sample.yar text.txt` in the terminal 
-  In the terminal if your text file respect one of the condition, it will print 'SectionSample text.txt` 
-  Retry after modifying your text file to respect one of the condition 

Reminder in a Linux terminal: 
  - The `cd FolderName` command moves to the FolderName folder.  
  - The `cd ..` command moves to the root folder of the one you are in 
  - The `ls` command displays the contents of the folder you're currently in

To run our YARA rule we will use the keyword `yara` to access the yara engine, for Windows you have to specify either the `yara32` or `yara64` bit version. The name of the rule file (the `. yar` file) and then the file we want to test. 

```bash 
┌──(yara@yara-virtual-machine)-[~/Documents/Yara_rules/Exercices/demo]
└─$ yara sample.yar text.txt
SectionSample test.txt
```
Sometimes, we might want to check our entire file system, and hence we can use `. ` in place of the file we want to test.


Checking over one file, i.e. the rest of the folder.

```bash
┌──(yara@yara-virtual-machine)-[~/Documents/Yara_rules/Exercices/demo]
└─$ yara sample.yar . 
HexSample ./falseTest.txt
SectionSample ./sample.yar
HexSample ./sample.yar
headmind ./sample.yar
SectionSample ./text.txt
```
Note that sample.yar respect all it's own rules as expected.

If you want the rule to recursively test all folders use the `-r `/ `--recursive` parameter 

If you want to print the meta-data of the rule, use the `--print-meta` / `-m` parameter. And to print only the fail match `--negate` / `-n`.

Find the other possibilities with `yara --help`

###Experiment

