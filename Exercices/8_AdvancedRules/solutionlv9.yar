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

rule JumpExample1
{
        strings:
            $hex_string = { 7A 79 6D 6A 61 }

        condition:
            $hex_string
}

rule JumpExample2
{
        strings:
            $hex_string = { 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61}

        condition:
            $hex_string
}
rule JumpExample3
{
        strings:
            $hex_string = { 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61 [-] 7A 79 6D 6A 61}

        condition:
            $hex_string
}

rule AlternativeExample1
{
    strings:
        $hex_string = {  20 [-] 20 [-] 20 [-] 20 ( 6A 6F 6B 6D 69 | 68 6F 78 66 69 )}
    
    condition:
        $hex_string
}


rule stringText{

    strings:
        $hex_string = "Je te l'avais dit :\r" 
   
    condition:
        $hex_string
}

rule stringText2{

    strings:
        $hex_string = "\t" 
   
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
        $hex_string = "Non uRna At" nocase
    
    condition:
        $hex_string
}

rule XorExample{
    strings:
        $xor_string = "Rvbmg#of#`kbw#pf#obuf/#jo#ub#sofvuljq" xor
    
    condition:
        $xor_string

}

rule XorExample1{
    strings:
        $xor_string = "id placerat leo hendrerit ac." xor
    
    condition:
        $xor_string

}
