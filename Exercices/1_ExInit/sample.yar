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



rule HexSample : OUI {
  meta:
  /*
    This is a multi-line comment ...
*/
    author = "Descartes"
    description = "YARA rule check false en hexa"
    tags = "OUI"

  strings:
    $b = {66 61 6C 73 65} //false en hexa
  
  condition:
   $b 
}

