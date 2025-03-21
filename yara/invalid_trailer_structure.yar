/*
   Yara Rule Set Custom
   Author: Jfisto
   Date: 2025-03-21
   Identifier: Custom
   Reference: https://github.com/jfisto/signature-base-yara/new/main
*/

rule JSOCTEST_invalid_trailer_structure : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic at 0 and not $reg0 and not $reg1
}
