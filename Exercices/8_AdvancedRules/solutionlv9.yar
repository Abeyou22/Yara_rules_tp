rule WildcarExample1
{
    strings:
        $hex_strings = { 54 ?? 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 3? 20 65 6E 20 6C 61 74 69 6E }

    condition:
        $hex_strings
}

rule WildcarExample2
{
    strings:
        $hex_strings = { 54 65 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 3? 20 65 6E 20 6C 61 74 69 6E }

    condition:
        $hex_strings
}

rule WildcarExample3
{
    strings:
        $hex_strings = { 54 ?? 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 31 20 65 6E 20 6C 61 74 69 6E }

    condition:
        $hex_strings
}

rule NotExample
{
    strings:
        $hex_string = { 54 ?? 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 ~?1 20 65 6E 20 6C 61 74 69 6E }
    condition:
        $hex_string
}

rule NotExample2
{
    strings:
        $hex_string = { 54 ~65 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 ?? 20 65 6E 20 6C 61 74 69 6E }
    condition:
        $hex_string
}

rule AlternativeExample
{
    strings:
        $hex_string = { 69 6E 0A ( 0A | 20 20 ) 4C 6F }
    
    condition:
        $hex_string
}

rule case
{
    strings:
        $hex_string = "MorBi" 
    
    condition:
        $hex_string
}

rule noCase
{
    strings:
        $hex_string = "MorBi" nocase
    
    condition:
        $hex_string
}