rule SectionSample{
  meta:
  /*
    This is a multi-line comment ...
*/
    author = "Descartes"
    description = "Simple YARA rule"

  strings:
    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
    $b = {66 61 6C 73 95}
    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
  
  condition:
   any of them //checks whether a file has any of the above rules //$a or $b or $c
}



rule HexSample{
  meta:
  /*
    This is a multi-line comment ...
*/
    author = "Descartes"
    description = "YARA rule check false en hexa"

  strings:
    $b = {66 61 6C 73 65} //false en hexa
  
  condition:
   $b 
}




rule headmind{
  meta:
    author = "Descartes"
    description = "YARA rule check headmind"

  strings:
    $b = "Headmind" //false en hexa
    $c = {25 50 44}
  
  condition:
   $b or $c
}