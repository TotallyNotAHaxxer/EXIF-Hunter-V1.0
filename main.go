/*
........................................................................................
. Developer -> ArkAngeL43
. Based off -> The image injection lib, my own forked verison of this lib
. Orgin     -> Base0
. Type      -> CLI
. IMG Form  -> PNG
. DATA FORM -> IN=BASED64/BINARY OUT=ASCII
. Organ     -> Scare_Sec_Hackers Offical cyber security team
.
.
.
. This program uses a rewrite of the lib imginject from the authors of the BHG Book
. it is meant to be used for image injection and stegenography purposes
.
. I felt the reason this lib needed to be modified was because of how little information it was
. giving out, personally this is my opinion but i think it would be better if libs like this
. gave out more information
*/
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"image/color"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bndr/gotabulate"
	sm "github.com/flopp/go-staticmaps"
	"github.com/fogleman/gg"
	"github.com/golang/geo/s2"
	"github.com/rwcarlsen/goexif/exif"
	"github.com/spf13/pflag"
)

// setting jpeg and JPG regex constant
const (
	IMG_REG = "[^\\s]+(.*?)\\.(jpg|jpeg|JPG|JPEG|)$"
)

//setting variables
var (
	flags = pflag.FlagSet{SortFlags: false}
	opts  CmdLineOpts
	// these are all pretty defualt to have in my scripts
	// i use it alot XD
	banner     = "txt/banner.txt"
	clear_hex  = "\x1b[H\x1b[2J\x1b[3J"
	now        = time.Now()
	formatDate = now.Format("15:04:05")
	BLK        = "\033[0;30m"
	RED        = "\033[0;31m"
	GRN        = "\033[0;32m"
	YEL        = "\033[0;33m"
	BLU        = "\033[0;34m"
	MAG        = "\033[0;35m"
	CYN        = "\033[0;36m"
	WHT        = "\033[0;37m"
	BBLK       = "\033[1;30m"
	BRED       = "\033[1;31m"
	BGRN       = "\033[1;32m"
	BYEL       = "\033[1;33m"
	BBLU       = "\033[1;34m"
	BMAG       = "\033[1;35m"
	BCYN       = "\033[1;36m"
	BWHT       = "\033[1;37m"
	UBLK       = "\033[4;30m"
	URED       = "\033[4;31m"
	UGRN       = "\033[4;32m"
	UYEL       = "\033[4;33m"
	UBLU       = "\033[4;34m"
	UMAG       = "\033[4;35m"
	UCYN       = "\033[4;36m"
	UWHT       = "\033[4;37m"
	BLKB       = "\033[40m"
	REDB       = "\033[41m"
	GRNB       = "\033[42m"
	YELB       = "\033[43m"
	BLUB       = "\033[44m"
	MAGB       = "\033[45m"
	CYNB       = "\033[46m"
	WHTB       = "\033[47m"
	BLKHB      = "\033[0;100m"
	REDHB      = "\033[0;101m"
	GRNHB      = "\033[0;102m"
	YELHB      = "\033[0;103m"
	BLUHB      = "\033[0;104m"
	MAGHB      = "\033[0;105m"
	CYNHB      = "\033[0;106m"
	WHTHB      = "\033[0;107m"
	HBLK       = "\033[0;90m"
	HRED       = "\033[0;91m"
	HGRN       = "\033[0;92m"
	HYEL       = "\033[0;93m"
	HBLU       = "\033[0;94m"
	HMAG       = "\033[0;95m"
	HCYN       = "\033[0;96m"
	HWHT       = "\033[0;97m"
	BHBLK      = "\033[1;90m"
	BHRED      = "\033[1;91m"
	BHGRN      = "\033[1;92m"
	BHYEL      = "\033[1;93m"
	BHBLU      = "\033[1;94m"
	BHMAG      = "\033[1;95m"
	BHCYN      = "\033[1;96m"
	BHWHT      = "\033[1;97m"
	chunkType  string
	IMG_png    MetaChunk
	m          MetaChunk
)

// REGEX for filepath pilaging for massive image search
var regex_type_image = []*regexp.Regexp{
	regexp.MustCompile(`(?i)jpg`),
	regexp.MustCompile(`(?i).jpg`),
	regexp.MustCompile(`(?i)jpeg`),
	regexp.MustCompile(`(?i).jpeg`),
}

// start out with restructuring the lib into a built in module
// this part is the options
type CmdLineOpts struct {
	Input       string
	Output      string
	Meta        bool
	Suppress    bool
	Offset      string
	Inject      bool
	Payload     string
	Type        string
	Encode      bool
	Decode      bool
	Key         string
	test_jpeg   bool
	Extract_ZIP bool
	INJECT_ZIP  bool
	ZIPFP       string
	hexdump     bool
	geo         bool
	walk        bool
	walkerfp    bool
	discover    bool
}

type FileSig struct {
	Sign       string
	SuffixFile string
	FileFormat string
}

// fils signotat

var massSign = []FileSig{
	{`474946`, `*.gif`, `GIF files`},
	{`GIF89a`, `*.gif`, `GIF files`},
	{`FFD8FF`, `*.jpg`, `JPEG files`},
	{`JFIF`, `*.jpg`, `JPEG files`},
	{`504B03`, `*.zip`, `ZIP files`},
	{`25504446`, `*.pdf`, `PDF files`},
	{`%PDF`, `*.pdf`, `PDF files`},
	{`006E1EF0`, `*.ppt`, `PPT`},
	{`A0461DF0`, `*.ppt`, `PPT`},
	{`ECA5C100`, `*.doc`, `Doc file`},
	{`000100005374616E64617264204A6574204442`, `*.mdb`, `Microsoft database`},
	{`Standard Jet DB`, `*.mdb`, `Microsoft database`},
	{`2142444E`, `*.pst`, `PST file`},
	{`!BDN`, `*.pst`, `PST file`},
	{`0908100000060500`, `*.xls`, `XLS file`},
	{`D0CF11E0A1B11AE1`, `*.msi`, `MSI file`},
	{`D0CF11E0A1B11AE1`, `*.doc`, `DOC`},
	{`D0CF11E0A1B11AE1`, `*.xls`, `Excel`},
	{`D0CF11E0A1B11AE1`, `*.vsd`, `Visio`},
	{`D0CF11E0A1B11AE1`, `*.ppt`, `PPT`},
	{`0A2525454F460A`, `*.pdf`, `PDF file`},
	{`.%%EOF.`, `*.pdf`, `PDF file`},
	{`4040402000004040`, `*.hlp`, `HLP file`},
	{`465753`, `*.swf`, `SWF file`},
	{`FWS`, `*.swf`, `SWF file`},
	{`CWS`, `*.swf`, `SWF file`},
	{`494433`, `*.mp3`, `MP3 file`},
	{`ID3`, `*.mp3`, `MP3 file`},
	{`MSCF`, `*.cab`, `Cab file`},
	{`0x4D534346`, `*.cab`, `Cab file`},
	{`ITSF`, `*.chm`, `Compressed Help`},
	{`49545346`, `*.chm`, `Compressed Help`},
	{`4C00000001140200`, `*.lnk`, `Link file`},
	{`4C01`, `*.obj`, `OBJ file`},
	{`4D4D002A`, `*.tif`, `TIF graphics`},
	{`MM`, `*.tif`, `TIF graphics`},
	{`000000186674797033677035`, `*.mp4`, `MP4 Video`},
	{`ftyp3gp5`, `*.mp4`, `MP4 Video`},
	{`0x00000100`, `*.ico`, `Icon file`},
	{`300000004C664C65`, `*.evt`, `Event file`},
	{`LfLe`, `*.evt`, `Event file`},
	{`38425053`, `*.psd`, `Photoshop file`},
	{`8BPS`, `*.psd`, `Photoshop file`},
	{`4D5A`, `*.ocx`, `Active X`},
	{`4D6963726F736F66742056697375616C2053747564696F20536F6C7574696F6E2046696C65`, `*.sln`, `Microsft SLN file`},
	{`Microsoft Visual Studio Solution File`, `*.sln`, `Microsft SLN file`},
	{`504B030414000600`, `*.docx`, `Microsoft DOCX file`},
	{`504B030414000600`, `*.pptx`, `Microsoft PPTX file`},
	{`504B030414000600`, `*.xlsx`, `Microsoft XLSX file`},
	{`504B0304140008000800`, `*.xlsx`, `Java JAR file`},
	{`415649204C495354`, `*.avi`, `AVI file`},
	{`AVI LIST`, `*.avi`, `AVI file`},
	{`57415645666D7420`, `*.wav`, `WAV file`},
	{`WAVEfmt`, `*.wav`, `WAV file`},
	{`Rar!`, `*.rar`, `RAR file`},
	{`526172211A0700`, `*.rar`, `RAR file`},
	{`52657475726E2D506174683A20`, `*.eml`, `EML file`},
	{`Return-Path:`, `*.eml`, `EML file`},
	{`6D6F6F76`, `*.mov`, `MOV file`},
	{`moov`, `*.mov`, `MOV file`},
	{`7B5C72746631`, `*.rtf`, `RTF file`},
	{`{\rtf1`, `*.rtf`, `RTF file`},
	{`89504E470D0A1A0A`, `*.png`, `PNG file`},
	{`PNG`, `*.png`, `PNG file`},
	{`C5D0D3C6`, `*.eps`, `EPS file`},
	{`CAFEBABE`, `*.class`, `Java class file`},
	{`D7CDC69A`, `*.WMF`, `WMF file`},
}

// this second part will be the commands.go file

const (
	endChunkType = "IEND"
)

/*
----------------------------------------------------------------------------------------------------------

START OF IDENTIFYING EXE FILES FOR WINDOWS, PORTED FROM PERL3.9

this is how we should be able to identify / inject EXE files, this is currently experimental

but it may work for further notices


var define_exe = []byte{
		"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x40\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21",
		"\xb8\x01\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53".
		"\x20\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x50\x45\x00\x00\x4c\x01\x08\x00\x16\x21\xa3\x4f\x00\xe0\x00\x0f\x03\x0b\x01\x02\x16\x00",
		"\x0c\x00\x00\x00\x1a\x00\x00\x00\x02\x00\x00\x6c\x12\x00\x00\x00\x10\x00\x00\x00\x20\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\x04\x00\x00\x00".
		"\x01\x00\x00\x00\x04\x00\x90\x00\x00\x00\x04\x00\x00\x04\x1b\x01\x00\x03\x00\x20\x00\x00\x10"."\x00" x 4 ."\x10\x00\x00\x10".
		"\x00\x10\x00\x60\x00\x00\x94\x03\x00\x80\x00\x00\x18\x00\xcc\x60\x00\x00\x7c"."\x00" x 27 ."\x2e\x74\x65\x78".
		"\x74\x00\x00\x00\xfc\x0b\x00\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x60\x00\x30\x60\x2e\x64\x61\x74\x61\x00\x00\x00\x10"."\x00" x 4 .
		"\x20\x00\x00\x00\x02\x00\x00\x00\x10"."\x00" x 14 ."\x40\x00\x30\xc0\x2e\x72\x64\x61\x74\x61\x00\x00\x24\x01\x00\x00\x00\x30\x00\x00\x00\x02\x00\x00\x00".
		"\x12"."\x00" x 14 ."\x40\x00\x30\x40\x2e\x65\x68\x5f\x66\x72\x61\x6d\xe0"."\x00" x 4 ."\x40\x00\x00\x00\x02\x00\x00\x00\x14"."\x00" x 14 ."\x40\x00\x30\x40".
		"\x2e\x62\x73\x73"."\x00" x 4 ."\x78"."\x00" x 4 ."\x50"."\x00" x 22 ."\x80\x00\x30\xc0\x2e\x69\x64\x61\x74\x61\x00\x00\x94\x03\x00\x00\x00\x60\x00\x00\x00".
		"\x04\x00\x00\x00\x16"."\x00" x 14 ."\x40\x00\x30\xc0\x2e\x43\x52\x54"."\x00" x 4 ."\x18"."\x00" x 4 ."\x70\x00\x00\x00\x02\x00\x00\x00\x1a"."\x00" x 14 .
		"\x40\x00\x30\xc0\x2e\x74\x6c\x73"."\x00" x 4 ."\x20"."\x00" x 4 ."\x80\x00\x00\x00\x02\x00\x00\x00\x1c"."\x00" x 14 ."\x40\x00\x30\xc0"."\x00" x 328 ."\x55".
		"\x89\xe5\x53\x83\xec\x34\xa1\x74\x30\x40\x00\x85\xc0\x74\x1c\xc7\x44\x24\x08"."\x00" x 4 ."\xc7\x44\x24\x04\x02\x00\x00\x00\xc7\x04\x24"."\x00" x 4 ."\xff".
		"\xd0\x83\xec\x0c\xc7\x04\x24\x10\x11\x40\x00\xe8\x34\x0b\x00\x00\x50\xe8\x66\x04\x00\x00\xe8\x41\x05\x00\x00\xc7\x45\xf0"."\x00" x 4 ."\x8d\x45\xf0\x89\x44".
		"\x24\x10\xa1\x00\x20\x40\x00\x89\x44\x24\x0c\x8d\x45\xf4\x89\x44\x24\x08\xc7\x44\x24\x04\x04\x50\x40\x00\xc7\x04\x24\x00\x50\x40\x00\xe8\x97\x0a\x00\x00".
		"\xa1\x30\x50\x40\x00\x85\xc0\x75\x4a\xe8\x91\x0a\x00\x00\x8b\x15\x04\x20\x40\x00\x89\x10\xe8\x2c\x06\x00\x00\x83\xe4\xf0\xe8\x6c\x08\x00\x00\xe8\x7f\x0a".
		"\x00\x00\x8b\x00\x89\x44\x24\x08\xa1\x04\x50\x40\x00\x89\x44\x24\x04\xa1\x00\x50\x40\x00\x89\x04\x24\xe8\xd3\x02\x00\x00\x89\xc3\xe8\x64\x0a\x00\x00\x89".
		"\x1c\x24\xe8\xac\x0a\x00\x00\xa3\x04\x20\x40\x00\x89\x44\x24\x04\x8b\x1d\x14\x61\x40\x00\x8b\x43\x10\x89\x04\x24\xe8\x4a\x0a\x00\x00\xa1\x30\x50\x40\x00".
		"\x89\x44\x24\x04\x8b\x43\x30\x89\x04\x24\xe8\x36\x0a\x00\x00\xa1\x30\x50\x40\x00\x89\x44\x24\x04\x8b\x43\x50\x89\x04\x24\xe8\x22\x0a\x00\x00\xe9\x6f\xff".
		"\xff\xff\x90\x55\x89\xe5\x53\x83\xec\x14\x8b\x45\x08\x8b\x00\x8b\x00\x3d\x91\x00\x00\xc0\x77\x3b\x3d\x8d\x00\x00\xc0\x72\x4c\xbb\x01\x00\x00\x00\xc7\x44".
		"\x24\x04"."\x00" x 4 ."\xc7\x04\x24\x08\x00\x00\x00\xe8\xef\x09\x00\x00\x83\xf8\x01\x0f\x84\xed\x00\x00\x00\x85\xc0\x0f\x85\x9a\x00\x00\x00\x31\xc0\x83\xc4".
		"\x14\x5b\xc9\xc2\x04\x00\x3d\x94\x00\x00\xc0\x74\x4d\x3d\x96\x00\x00\xc0\x74\x18\x3d\x93\x00\x00\xc0\x75\xe1\xeb\xb5\x90\x3d\x05\x00\x00\xc0\x74\x3d\x3d".
		"\x1d\x00\x00\xc0\x75\xd0\xc7\x44\x24\x04"."\x00" x 4 ."\xc7\x04\x24\x04\x00\x00\x00\xe8\x9a\x09\x00\x00\x83\xf8\x01\x74\x64\x85\xc0\x74\xb3\xc7\x04\x24\x04".
		"\x00\x00\x00\xff\xd0\xb8"."\xff" x 4 ."\xeb\xa5\x90\x31\xdb\xe9\x76\xff\xff\xff\x90\xc7\x44\x24\x04"."\x00" x 4 ."\xc7\x04\x24\x0b\x00\x00\x00\xe8\x64\x09".
		"\x00\x00\x83\xf8\x01\x74\x4a\x85\xc0\x0f\x84\x79\xff\xff\xff\xc7\x04\x24\x0b\x00\x00\x00\xff\xd0\xb8"."\xff" x 4 ."\xe9\x68\xff\xff\xff\xc7\x04\x24\x08\x00".
		"\x00\x00\xff\xd0\xb8"."\xff" x 4 ."\xe9\x55\xff\xff\xff\xc7\x44\x24\x04\x01\x00\x00\x00\xc7\x04\x24\x04\x00\x00\x00\xe8\x1d\x09\x00\x00\x83\xc8\xff\xe9\x39".
		"\xff\xff\xff\xc7\x44\x24\x04\x01\x00\x00\x00\xc7\x04\x24\x0b\x00\x00\x00\xe8\x01\x09\x00\x00\x83\xc8\xff\xe9\x1d\xff\xff\xff\xc7\x44\x24\x04\x01\x00\x00".
		"\x00\xc7\x04\x24\x08\x00\x00\x00\xe8\xe5\x08\x00\x00\x85\xdb\x75\x0a\xb8"."\xff" x 4 ."\xe9\xfb\xfe\xff\xff\xe8\x22\x03\x00\x00\x83\xc8\xff\xe9\xee\xfe\xff".
		"\xff\x66\x90\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x01\x00\x00\x00\xff\x15\x0c\x61\x40\x00\xe8\x7c\xfd\xff\xff\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x02\x00".
		"\x00\x00\xff\x15\x0c\x61\x40\x00\xe8\x64\xfd\xff\xff\x55\x89\xe5\x83\xec\x08\xa1\x24\x61\x40\x00\xc9\xff\xe0\x66\x90\x55\x89\xe5\x83\xec\x08\xa1\x18\x61".
		"\x40\x00\xc9\xff\xe0\x90\x90\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x00\x30\x40\x00\xe8\xae\x08\x00\x00\x52\x85\xc0\x74\x65\xc7\x44\x24\x04\x13\x30\x40\x00".
		"\x89\x04\x24\xe8\xa1\x08\x00\x00\x83\xec\x08\x85\xc0\x74\x11\xc7\x44\x24\x04\x08\x50\x40\x00\xc7\x04\x24\x00\x40\x40\x00\xff\xd0\x8b\x0d\x0c\x20\x40\x00".
		"\x85\xc9\x74\x31\xc7\x04\x24\x29\x30\x40\x00\xe8\x6b\x08\x00\x00\x52\x85\xc0\x74\x2a\xc7\x44\x24\x04\x37\x30\x40\x00\x89\x04\x24\xe8\x5e\x08\x00\x00\x83".
		"\xec\x08\x85\xc0\x74\x09\xc7\x04\x24\x0c\x20\x40\x00\xff\xd0\xc9\xc3\xb8"."\x00" x 4 ."\xeb\xa7\x90\xb8"."\x00" x 4 ."\xeb\xe2\x90\x55\x89\xe5\x83\xec\x18".
		"\xc7\x04\x24\x00\x30\x40\x00\xe8\x22\x08\x00\x00\x51\x85\xc0\x74\x25\xc7\x44\x24\x04\x4b\x30\x40\x00\x89\x04\x24\xe8\x15\x08\x00\x00\x83\xec\x08\x85\xc0".
		"\x74\x09\xc7\x04\x24\x00\x40\x40\x00\xff\xd0\xc9\xc3\x8d\x76\x00\xb8"."\x00" x 4 ."\xeb\xe7\x90\x8d\x4c\x24\x04\x83\xe4\xf0\xff\x71\xfc\x55\x89\xe5\x51".
		"\x83\xec\x24\xe8\x62\x05\x00\x00\xc7\x44\x24\x14\x01\x00\x00\x00\xc7\x44\x24\x10"."\x00" x 4 ."\xc7\x44\x24\x0c"."\x00" x 4 ."\xc7\x44\x24\x08\x64\x30\x40".
		"\x00\xc7\x44\x24\x04\x6d\x30\x40\x00\xc7\x04\x24"."\x00" x 4 ."\xe8\x8e\x07\x00\x00\x83\xec\x18\xb8"."\x00" x 4 ."\x8b\x4d\xfc\xc9\x8d\x61\xfc\xc3\x90\x90".
		"\x55\x89\xe5\x83\xec\x18\x8b\x45\x0c\x83\xf8\x03\x74\x04\x85\xc0\x75\x16\x8b\x55\x10\x89\x54\x24\x08\x89\x44\x24\x04\x8b\x45\x08\x89\x04\x24\xe8\x84\x06".
		"\x00\x00\xb8\x01\x00\x00\x00\xc9\xc2\x0c\x00\x8d\x76\x00\x55\x89\xe5\x53\x83\xec\x14\x8b\x45\x0c\x83\x3d\x40\x50\x40\x00\x02\x74\x0a\xc7\x05\x40\x50\x40".
		"\x00\x02\x00\x00\x00\x83\xf8\x02\x74\x12\x48\x74\x3f\xb8\x01\x00\x00\x00\x83\xc4\x14\x5b\xc9\xc2\x0c\x00\x66\x90\xbb\x14\x70\x40\x00\x81\xfb\x14\x70\x40".
		"\x00\x74\xe4\x8d\x76\x00\x8b\x03\x85\xc0\x74\x02\xff\xd0\x83\xc3\x04\x81\xfb\x14\x70\x40\x00\x75\xed\xb8\x01\x00\x00\x00\x83\xc4\x14\x5b\xc9\xc2\x0c\x00".
		"\x8b\x45\x10\x89\x44\x24\x08\xc7\x44\x24\x04\x01\x00\x00\x00\x8b\x45\x08\x89\x04\x24\xe8\xfa\x05\x00\x00\xeb\xa5\x55\x89\xe5\x31\xc0\xc9\xc3\x90\x55\x89".
		"\xe5\x53\x9c\x9c\x58\x89\xc2\x35\x00\x00\x20\x00\x50\x9d\x9c\x58\x9d\x31\xd0\xa9\x00\x00\x20\x00\x0f\x84\xa4\x00\x00\x00\x31\xc0\x0f\xa2\x85\xc0\x0f\x84".
		"\x98\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\xa2\xf6\xc6\x01\x74\x07\x83\x0d\x34\x50\x40\x00\x01\xf6\xc6\x80\x74\x07\x83\x0d\x34\x50\x40\x00\x02\xf7\xc2\x00".
		"\x00\x80\x00\x74\x07\x83\x0d\x34\x50\x40\x00\x04\xf7\xc2\x00\x00\x00\x01\x74\x07\x83\x0d\x34\x50\x40\x00\x08\xf7\xc2\x00\x00\x00\x02\x74\x07\x83\x0d\x34".
		"\x50\x40\x00\x10\x81\xe2\x00\x00\x00\x04\x74\x07\x83\x0d\x34\x50\x40\x00\x20\xf6\xc1\x01\x74\x07\x83\x0d\x34\x50\x40\x00\x40\x80\xe5\x20\x75\x30\xb8\x00".
		"\x00\x00\x80\x0f\xa2\x3d\x00\x00\x00\x80\x76\x1e\xb8\x01\x00\x00\x80\x0f\xa2\x85\xd2\x78\x23\x81\xe2\x00\x00\x00\x40\x74\x0b\x81\x0d\x34\x50\x40\x00\x00".
		"\x02\x00\x00\x90\x5b\xc9\xc3\x90\x81\x0d\x34\x50\x40\x00\x80\x00\x00\x00\xeb\xc4\x81\x0d\x34\x50\x40\x00\x00\x01\x00\x00\xeb\xd1\x55\x89\xe5\xdb\xe3\xc9".
		"\xc3\x90\x55\x89\xe5\x56\x53\x83\xec\x10\x8d\x75\x0c\x8b\x1d\x14\x61\x40\x00\x83\xc3\x40\x89\x5c\x24\x0c\xc7\x44\x24\x08\x17\x00\x00\x00\xc7\x44\x24\x04".
		"\x01\x00\x00\x00\xc7\x04\x24\x78\x30\x40\x00\xe8\x7c\x05\x00\x00\x89\x74\x24\x08\x8b\x45\x08\x89\x44\x24\x04\x89\x1c\x24\xe8\x71\x05\x00\x00\xe8\x74\x05".
		"\x00\x00\x55\x89\xe5\x57\x56\x53\x83\xec\x4c\x89\xc3\x89\xd6\x85\xc9\x75\x0b\x8d\x65\xf4\x5b\x5e\x5f\xc9\xc3\x8d\x76\x00\xc7\x44\x24\x08\x1c\x00\x00\x00".
		"\x8d\x45\xc8\x89\x44\x24\x04\x89\x1c\x24\x89\x4d\xc4\xe8\x7e\x05\x00\x00\x83\xec\x0c\x85\xc0\x8b\x4d\xc4\x0f\x84\x88\x00\x00\x00\x8b\x45\xdc\x83\xf8\x40".
		"\x74\x74\x83\xf8\x04\x74\x6f\x8d\x55\xe4\x89\x54\x24\x0c\xc7\x44\x24\x08\x40\x00\x00\x00\x8b\x45\xd4\x89\x44\x24\x04\x8b\x45\xc8\x89\x04\x24\x89\x55\xc0".
		"\x89\x4d\xc4\xe8\x44\x05\x00\x00\x83\xec\x10\x8b\x45\xdc\x8b\x4d\xc4\x89\xdf\xf3\xa4\x83\xf8\x40\x8b\x55\xc0\x74\x84\x83\xf8\x04\x0f\x84\x7b\xff\xff\xff".
		"\x89\x54\x24\x0c\x8b\x45\xe4\x89\x44\x24\x08\x8b\x45\xd4\x89\x44\x24\x04\x8b\x45\xc8\x89\x04\x24\xe8\x09\x05\x00\x00\x83\xec\x10\x8d\x65\xf4\x5b\x5e\x5f".
		"\xc9\xc3\x66\x90\x89\xdf\xf3\xa4\x8d\x65\xf4\x5b\x5e\x5f\xc9\xc3\x89\x5c\x24\x08\xc7\x44\x24\x04\x1c\x00\x00\x00\xc7\x04\x24\x90\x30\x40\x00\xe8\xd0\xfe".
		"\xff\xff\x55\x89\xe5\x57\x56\x53\x83\xec\x2c\xa1\x38\x50\x40\x00\x85\xc0\x74\x0a\x83\xc4\x2c\x5b\x5e\x5f\xc9\xc3\x66\x90\xc7\x05\x38\x50\x40\x00\x01\x00".
		"\x00\x00\xb8\x24\x31\x40\x00\x2d\x24\x31\x40\x00\x83\xf8\x07\x7e\xdd\xbb\x24\x31\x40\x00\x83\xf8\x0b\x7e\x61\x8b\x3d\x24\x31\x40\x00\x85\xff\x75\x0b\x8b".
		"\x35\x28\x31\x40\x00\x85\xf6\x74\x3d\x90\x81\xfb\x24\x31\x40\x00\x73\xb6\xbe\x00\x00\x40\x00\x8d\x7d\xe0\x8b\x43\x04\x01\xf0\x8b\x10\x03\x13\x89\x55\xe0".
		"\xb9\x04\x00\x00\x00\x89\xfa\xe8\xa0\xfe\xff\xff\x83\xc3\x08\x81\xfb\x24\x31\x40\x00\x72\xdd\x83\xc4\x2c\x5b\x5e\x5f\xc9\xc3\x90\x8b\x0d\x2c\x31\x40\x00".
		"\x85\xc9\x75\x13\xbb\x30\x31\x40\x00\x90\x8b\x13\x85\xd2\x75\xae\x8b\x43\x04\x85\xc0\x75\xa7\x8b\x43\x08\x83\xf8\x01\x0f\x85\x02\x01\x00\x00\x83\xc3\x0c".
		"\x81\xfb\x24\x31\x40\x00\x0f\x83\x4a\xff\xff\xff\xb8\x00\x00\x40\x00\x03\x43\x04\x8b\x0b\x8b\xb1\x00\x00\x40\x00\x8b\x53\x08\x81\xe2\xff\x00\x00\x00\x83".
		"\xfa\x10\x74\x46\x83\xfa\x20\x74\x79\x83\xfa\x08\x74\x18\xc7\x45\xe4"."\x00" x 4 ."\x89\x54\x24\x04\xc7\x04\x24\xf8\x30\x40\x00\xe8\xc9\xfd\xff\xff\x90\x0f".
		"\xb6\x38\xf7\xc7\x80\x00\x00\x00\x74\x24\x81\xcf\x00\xff\xff\xff\x29\xcf\x81\xef\x00\x00\x40\x00\x8d\x34\x37\x89\x75\xe4\xeb\x2c\x8d\x76\x00\x0f\xb7\x38".
		"\xf7\xc7\x00\x80\x00\x00\x75\x61\x29\xcf\x89\xf9\x81\xe9\x00\x00\x40\x00\x01\xf1\x89\x4d\xe4\x83\xfa\x10\x74\x61\x83\xfa\x20\x74\x23\x83\xfa\x08\x75\x2b".
		"\xb9\x01\x00\x00\x00\x8d\x55\xe4\xe8\xba\xfd\xff\xff\xeb\x1c\x8b\x10\x29\xca\x81\xea\x00\x00\x40\x00\x01\xf2\x89\x55\xe4\xb9\x04\x00\x00\x00\x8d\x55\xe4".
		"\xe8\x9c\xfd\xff\xff\x83\xc3\x0c\xb8\x24\x31\x40\x00\x39\xd8\x0f\x87\x38\xff\xff\xff\xe9\x7d\xfe\xff\xff\x8d\x76\x00\x81\xcf\x00\x00\xff\xff\x29\xcf\x81".
		"\xef\x00\x00\x40\x00\x8d\x34\x37\x89\x75\xe4\xb9\x02\x00\x00\x00\x8d\x55\xe4\xe8\x63\xfd\xff\xff\xeb\xc5\x89\x44\x24\x04\xc7\x04\x24\xc4\x30\x40\x00\xe8".
		"\x05\xfd\xff\xff\x90\x55\x89\xe5\x83\xec\x08\xa1\x08\x20\x40\x00\x8b\x00\x85\xc0\x74\x1a\x8d\x76\x00\xff\xd0\xa1\x08\x20\x40\x00\x8d\x50\x04\x89\x15\x08".
		"\x20\x40\x00\x8b\x40\x04\x85\xc0\x75\xe9\xc9\xc3\x8d\x76\x00\x55\x89\xe5\x53\x83\xec\x14\x8b\x1d\xe8\x1b\x40\x00\x83\xfb\xff\x74\x22\x85\xdb\x74\x0c\x66".
		"\x90\xff\x14\x9d\xe8\x1b\x40\x00\x4b\x75\xf6\xc7\x04\x24\x88\x18\x40\x00\xe8\xb6\xf9\xff\xff\x83\xc4\x14\x5b\xc9\xc3\x31\xdb\xeb\x02\x89\xc3\x8d\x43\x01".
		"\x8b\x14\x85\xe8\x1b\x40\x00\x85\xd2\x75\xf0\xeb\xc8\x66\x90\x55\x89\xe5\x83\xec\x08\x8b\x0d\x3c\x50\x40\x00\x85\xc9\x74\x04\xc9\xc3\x66\x90\xc7\x05\x3c".
		"\x50\x40\x00\x01\x00\x00\x00\xc9\xeb\x93\x90\x90\x90\x55\x89\xe5\x56\x53\x83\xec\x10\xa1\x44\x50\x40\x00\x85\xc0\x75\x07\x8d\x65\xf8\x5b\x5e\xc9\xc3\xc7".
		"\x04\x24\x48\x50\x40\x00\xe8\x50\x02\x00\x00\x51\x8b\x1d\x60\x50\x40\x00\x85\xdb\x74\x2a\x90\x8b\x03\x89\x04\x24\xe8\x42\x02\x00\x00\x52\x89\xc6\xe8\x42".
		"\x02\x00\x00\x85\xc0\x75\x0c\x85\xf6\x74\x08\x8b\x43\x04\x89\x34\x24\xff\xd0\x8b\x5b\x08\x85\xdb\x75\xd7\xc7\x04\x24\x48\x50\x40\x00\xe8\x27\x02\x00\x00".
		"\x50\x8d\x65\xf8\x5b\x5e\xc9\xc3\x8d\x76\x00\x55\x89\xe5\x53\x83\xec\x14\xa1\x44\x50\x40\x00\x85\xc0\x75\x08\x31\xc0\x8b\x5d\xfc\xc9\xc3\x90\xc7\x44\x24".
		"\x04\x0c\x00\x00\x00\xc7\x04\x24\x01\x00\x00\x00\xe8\x90\x01\x00\x00\x89\xc3\x85\xc0\x74\x37\x8b\x45\x08\x89\x03\x8b\x45\x0c\x89\x43\x04\xc7\x04\x24\x48".
		"\x50\x40\x00\xe8\xbb\x01\x00\x00\x50\xa1\x60\x50\x40\x00\x89\x43\x08\x89\x1d\x60\x50\x40\x00\xc7\x04\x24\x48\x50\x40\x00\xe8\xb8\x01\x00\x00\x53\x31\xc0".
		"\xeb\xa9\xb8"."\xff" x 4 ."\xeb\xa2\x55\x89\xe5\x53\x83\xec\x14\x8b\x5d\x08\xa1\x44\x50\x40\x00\x85\xc0\x75\x09\x31\xc0\x8b\x5d\xfc\xc9\xc3\x66\x90\xc7\x04".
		"\x24\x48\x50\x40\x00\xe8\x6c\x01\x00\x00\x51\x8b\x15\x60\x50\x40\x00\x85\xd2\x74\x18\x8b\x02\x39\xd8\x75\x0b\xeb\x42\x90\x8b\x08\x39\xd9\x74\x1e\x89\xc2".
		"\x8b\x42\x08\x85\xc0\x75\xf1\xc7\x04\x24\x48\x50\x40\x00\xe8\x55\x01\x00\x00\x52\x31\xc0\x8b\x5d\xfc\xc9\xc3\x90\x8b\x48\x08\x89\x4a\x08\x89\x04\x24\xe8".
		"\xe6\x00\x00\x00\xc7\x04\x24\x48\x50\x40\x00\xe8\x32\x01\x00\x00\x52\xeb\xdb\x8b\x42\x08\xa3\x60\x50\x40\x00\x89\xd0\xeb\xdd\x8d\x76\x00\x55\x89\xe5\x83".
		"\xec\x18\x8b\x45\x0c\x83\xf8\x01\x74\x3e\x72\x14\x83\xf8\x03\x75\x05\xe8\x7a\xfe\xff\xff\xb8\x01\x00\x00\x00\xc9\xc3\x8d\x76\x00\xe8\x6b\xfe\xff\xff\xa1".
		"\x44\x50\x40\x00\x48\x75\xe9\xc7\x05\x44\x50\x40"."\x00" x 5 ."\xc7\x04\x24\x48\x50\x40\x00\xe8\xe1\x00\x00\x00\x50\xeb\xd0\x66\x90\xa1\x44\x50\x40\x00".
		"\x85\xc0\x74\x13\xc7\x05\x44\x50\x40\x00\x01\x00\x00\x00\xb8\x01\x00\x00\x00\xc9\xc3\x66\x90\xc7\x04\x24\x48\x50\x40\x00\xe8\xbc\x00\x00\x00\x52\xeb\xde".
		"\x90\xff\x25\x00\x61\x40\x00\x90\x90\xff\x25\x08\x61\x40\x00\x90\x90\xff\x25\x04\x61\x40\x00\x90\x90\xff\x25\x10\x61\x40\x00\x90\x90\xff\x25\x1c\x61\x40".
		"\x00\x90\x90\xff\x25\x34\x61\x40\x00\x90\x90\xff\x25\x30\x61\x40\x00\x90\x90\xff\x25\x38\x61\x40\x00\x90\x90\xff\x25\x20\x61\x40\x00\x90\x90\xff\x25\x28".
		"\x61\x40\x00\x90\x90\xff\x25\x2c\x61\x40\x00\x90\x90\xff\x25\x40\x61\x40\x00\x90\x90\xff\x25\xec\x60\x40\x00\x90\x90\xff\x25\xd4\x60\x40\x00\x90\x90\xff".
		"\x25\xdc\x60\x40\x00\x90\x90\xff\x25\xe0\x60\x40\x00\x90\x90\xff\x25\xf8\x60\x40\x00\x90\x90\xff\x25\xf4\x60\x40\x00\x90\x90\xff\x25\xd0\x60\x40\x00\x90".
		"\x90\xff\x25\xf0\x60\x40\x00\x90\x90\xff\x25\xd8\x60\x40\x00\x90\x90\xff\x25\xe8\x60\x40\x00\x90\x90\xff\x25\xcc\x60\x40\x00\x90\x90\xff\x25\xe4\x60\x40".
		"\x00\x90\x90\x55\x89\xe5\x83\xec\x18\xe8\xe5\xf6\xff\xff\xc7\x04\x24\x48\x13\x40\x00\xe8\xb9\xf6\xff\xff\xc9\xc3\x90\x90\x90"."\xff" x 4 ."\xcc\x1b\x40".
		"\x00" x 5 .""."\xff" x 4 .""."\x00" x 8 .""."\xff" x 4 ."\x00\x40\x00\x00\xf8\x1b\x40"."\x00" x 501 ."\x6c\x69\x62\x67\x63\x63\x5f\x73\x5f\x64\x77\x32\x2d".
		"\x31\x2e\x64\x6c\x6c\x00\x5f\x5f\x72\x65\x67\x69\x73\x74\x65\x72\x5f\x66\x72\x61\x6d\x65\x5f\x69\x6e\x66\x6f\x00\x6c\x69\x62\x67\x63\x6a\x2d\x31\x32\x2e".
		"\x64\x6c\x6c\x00\x5f\x4a\x76\x5f\x52\x65\x67\x69\x73\x74\x65\x72\x43\x6c\x61\x73\x73\x65\x73\x00\x5f\x5f\x64\x65\x72\x65\x67\x69\x73\x74\x65\x72\x5f\x66".
		"\x72\x61\x6d\x65\x5f\x69\x6e\x66\x6f\x00\x00\x63\x61\x6c\x63\x2e\x65\x78\x65\x00\x6f\x70\x65\x6e\x00\x00\x00\x1c\x14\x40\x00\x4d\x69\x6e\x67\x77\x20\x72".
		"\x75\x6e\x74\x69\x6d\x65\x20\x66\x61\x69\x6c\x75\x72\x65\x3a\x0a\x00\x20\x20\x56\x69\x72\x74\x75\x61\x6c\x51\x75\x65\x72\x79\x20\x66\x61\x69\x6c\x65\x64".
		"\x20\x66\x6f\x72\x20\x25\x64\x20\x62\x79\x74\x65\x73\x20\x61\x74\x20\x61\x64\x64\x72\x65\x73\x73\x20\x25\x70"."\x00" x 4 ."\x20\x20\x55\x6e\x6b\x6e\x6f\x77".
		"\x6e\x20\x70\x73\x65\x75\x64\x6f\x20\x72\x65\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x25".
		"\x64\x2e\x0a\x00\x00\x00\x20\x20\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x70\x73\x65\x75\x64\x6f\x20\x72\x65\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x62\x69\x74\x20".
		"\x73\x69\x7a\x65\x20\x25\x64\x2e\x0a"."\x00" x 223 ."\x14"."\x00" x 7 ."\x01\x7a\x52\x00\x01\x7c\x08\x01\x1b\x0c\x04\x04\x88\x01\x00\x00\x20\x00\x00\x00".
		"\x1c\x00\x00\x00\x9c\xd2\xff\xff\x8b"."\x00" x 4 ."\x41\x0e\x08\x85\x02\x42\x0d\x05\x02\x78\x0a\xc5\x0c\x04\x04\x41\x0b\x00\x00\x20\x00\x00\x00\x40\x00\x00".
		"\x00\x04\xd3\xff\xff\x43"."\x00" x 4 ."\x41\x0e\x08\x85\x02\x42\x0d\x05\x75\x0a\xc5\x0c\x04\x04\x44\x0b\x00\x00\x00\x14"."\x00" x 7 ."\x01\x7a\x52\x00\x01".
		"\x7c\x08\x01\x1b\x0c\x04\x04\x88\x01\x00\x00\x28\x00\x00\x00\x1c\x00\x00\x00\x0c\xd3\xff\xff\x5a"."\x00" x 4 ."\x44\x0c\x01\x00\x49\x10\x05\x02\x75\x00\x41".
		"\x0f\x03\x75\x7c\x06\x02\x47\x0c\x01\x00\x44\x0c\x04\x04"."\x00" x 6 ."\x14"."\x00" x 7 ."\x01\x7a\x52\x00\x01\x7c\x08\x01\x1b\x0c\x04\x04\x88\x01\x00\x00".
		"\x1c\x00\x00\x00\x1c\x00\x00\x00\x04\xdb\xff\xff\x19"."\x00" x 4 ."\x41\x0e\x08\x85\x02\x42\x0d\x05\x55\xc5\x0c\x04\x04"."\x00" x 290 ."\x50\x60".
		"\x00" x 10 ."\x2c\x63\x00\x00\xcc\x60\x00\x00\x84\x60"."\x00" x 10 ."\x78\x63\x00\x00\x00\x61\x00\x00\xc4\x60"."\x00" x 10 ."\x88\x63\x00\x00\x40\x61".
		"\x00" x 22 ."\x48\x61\x00\x00\x60\x61\x00\x00\x78\x61\x00\x00\x86\x61\x00\x00\x96\x61\x00\x00\xaa\x61\x00\x00\xbc\x61\x00\x00\xd8\x61\x00\x00\xf0\x61\x00".
		"\x00\x0e\x62\x00\x00\x1c\x62\x00\x00\x2e\x62"."\x00" x 6 ."\x3e\x62\x00\x00\x4e\x62\x00\x00\x5e\x62\x00\x00\x6c\x62\x00\x00\x7e\x62\x00\x00\x88\x62\x00\x00".
		"\x90\x62\x00\x00\x9a\x62\x00\x00\xa6\x62\x00\x00\xae\x62\x00\x00\xb8\x62\x00\x00\xc2\x62\x00\x00\xca\x62\x00\x00\xd4\x62\x00\x00\xde\x62"."\x00" x 6 ."\xea".
		"\x62"."\x00" x 6 ."\x48\x61\x00\x00\x60\x61\x00\x00\x78\x61\x00\x00\x86\x61\x00\x00\x96\x61\x00\x00\xaa\x61\x00\x00\xbc\x61\x00\x00\xd8\x61\x00\x00\xf0\x61".
		"\x00\x00\x0e\x62\x00\x00\x1c\x62\x00\x00\x2e\x62"."\x00" x 6 ."\x3e\x62\x00\x00\x4e\x62\x00\x00\x5e\x62\x00\x00\x6c\x62\x00\x00\x7e\x62\x00\x00\x88\x62\x00".
		"\x00\x90\x62\x00\x00\x9a\x62\x00\x00\xa6\x62\x00\x00\xae\x62\x00\x00\xb8\x62\x00\x00\xc2\x62\x00\x00\xca\x62\x00\x00\xd4\x62\x00\x00\xde\x62"."\x00" x 6 .
		"\xea\x62"."\x00" x 6 ."\xcf\x00\x44\x65\x6c\x65\x74\x65\x43\x72\x69\x74\x69\x63\x61\x6c\x53\x65\x63\x74\x69\x6f\x6e\x00\xec\x00\x45\x6e\x74\x65\x72\x43\x72".
		"\x69\x74\x69\x63\x61\x6c\x53\x65\x63\x74\x69\x6f\x6e\x00\x00\x17\x01\x45\x78\x69\x74\x50\x72\x6f\x63\x65\x73\x73\x00\xfe\x01\x47\x65\x74\x4c\x61\x73\x74".
		"\x45\x72\x72\x6f\x72\x00\x00\x11\x02\x47\x65\x74\x4d\x6f\x64\x75\x6c\x65\x48\x61\x6e\x64\x6c\x65\x41\x00\x00\x41\x02\x47\x65\x74\x50\x72\x6f\x63\x41\x64".
		"\x64\x72\x65\x73\x73\x00\x00\xde\x02\x49\x6e\x69\x74\x69\x61\x6c\x69\x7a\x65\x43\x72\x69\x74\x69\x63\x61\x6c\x53\x65\x63\x74\x69\x6f\x6e\x00\x2e\x03\x4c".
		"\x65\x61\x76\x65\x43\x72\x69\x74\x69\x63\x61\x6c\x53\x65\x63\x74\x69\x6f\x6e\x00\x00\x74\x04\x53\x65\x74\x55\x6e\x68\x61\x6e\x64\x6c\x65\x64\x45\x78\x63".
		"\x65\x70\x74\x69\x6f\x6e\x46\x69\x6c\x74\x65\x72\x00\x95\x04\x54\x6c\x73\x47\x65\x74\x56\x61\x6c\x75\x65\x00\xbd\x04\x56\x69\x72\x74\x75\x61\x6c\x50\x72".
		"\x6f\x74\x65\x63\x74\x00\x00\xbf\x04\x56\x69\x72\x74\x75\x61\x6c\x51\x75\x65\x72\x79\x00\x00\x37\x00\x5f\x5f\x67\x65\x74\x6d\x61\x69\x6e\x61\x72\x67\x73".
		"\x00\x4d\x00\x5f\x5f\x70\x5f\x5f\x65\x6e\x76\x69\x72\x6f\x6e\x00\x00\x4f\x00\x5f\x5f\x70\x5f\x5f\x66\x6d\x6f\x64\x65\x00\x00\x63\x00\x5f\x5f\x73\x65\x74".
		"\x5f\x61\x70\x70\x5f\x74\x79\x70\x65\x00\x00\x93\x00\x5f\x63\x65\x78\x69\x74\x00\x00\x0a\x01\x5f\x69\x6f\x62\x00\x00\x7f\x01\x5f\x6f\x6e\x65\x78\x69\x74".
		"\x00\xaa\x01\x5f\x73\x65\x74\x6d\x6f\x64\x65\x00\x00\x47\x02\x61\x62\x6f\x72\x74\x00\x4e\x02\x61\x74\x65\x78\x69\x74\x00\x00\x53\x02\x63\x61\x6c\x6c\x6f".
		"\x63\x00\x00\x71\x02\x66\x72\x65\x65\x00\x00\x79\x02\x66\x77\x72\x69\x74\x65\x00\x00\xc2\x02\x73\x69\x67\x6e\x61\x6c\x00\x00\xec\x02\x76\x66\x70\x72\x69".
		"\x6e\x74\x66\x00\x00\x90\x00\x53\x68\x65\x6c\x6c\x45\x78\x65\x63\x75\x74\x65\x41"."\x00" x 4 ."\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00".
		"\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x4b\x45\x52\x4e\x45\x4c".
		"\x33\x32\x2e\x64\x6c\x6c"."\x00" x 4 ."\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14".
		"\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x14\x60\x00\x00\x6d\x73\x76\x63\x72\x74\x2e".
		"\x64\x6c\x6c\x00\x00\x28\x60\x00\x00\x53\x48\x45\x4c\x4c\x33\x32\x2e\x44\x4c\x4c"."\x00" x 113 ."\x1c\x14\x40\x00\xe8\x13\x40"."\x00" x 501 ."\x19\x80\x40".
		"\x00\x1c\x80\x40\x00\x20\x50\x40\x00\x04\x70\x40"."\x00" x 497;
}

-------------------------------------------------------------------------------------------------------------
	END OF EXE FILE IDENTIFICATION

*/

//Header holds the first byte (aka magic byte)
type Header struct {
	Header uint64 //  0:8
}

//Chunk represents a data byte chunk
type Chunk struct {
	Size uint32
	Type uint32
	Data []byte
	CRC  uint32
}

//MetaChunk inherits a Chunk struct
type MetaChunk struct {
	Chk    Chunk
	Offset int64
}

// add return error function
func che(err error, msg string, exit int) {
	if err != nil {
		fmt.Println(RED, "[!] Error: Fatal: ", msg, err)
		os.Exit(exit)
	}
}

func hex_conv(data string) string {
	// replace 0x or 0X with empty String
	numberStr := strings.Replace(data, "0x", "", -1)
	numberStr = strings.Replace(numberStr, "0X", "", -1)
	return numberStr
}

// hex dumper
func dumper(file string, buffer int) {
	hexed, err := os.Open(file)
	che(err, " Could not read or open this file -> ", 1)
	defer hexed.Close()
	reader := bufio.NewReader(hexed)
	buffer_ := make([]byte, buffer)
	fmt.Println("\n\t\033[38m[+] HEX DUMPING IN 5 SECONDS")
	time.Sleep(5 * time.Second)
	for {
		_, err := reader.Read(buffer_)
		che(err, "Could not read or properly set buffer", 1)
		fmt.Printf("\033[31m%s", hex.Dump(buffer_))
	}
}

func call_finder(cmds *CmdLineOpts) {
	fileJpg := cmds.Output
	file, err := os.Open(fileJpg)
	che(err, "Could not open output file", 1)
	bufferedReader := bufio.NewReader(file)
	fileStat, _ := file.Stat()
	for i := int64(0); i < fileStat.Size(); i++ {
		myByte, err := bufferedReader.ReadByte()
		che(err, "Could not read buffer byte", 1)
		if myByte == '\x50' {
			byteSlice := make([]byte, 3)
			byteSlice, err = bufferedReader.Peek(3)
			che(err, "Could not read peak", 1)
			if bytes.Equal(byteSlice, []byte{'\x4b', '\x03', '\x04'}) {
				log.Printf("Found zip signature at byte %d.", i)
			}
		}
	}
	for {
		var unz string
		fmt.Print("Unzip it? (Y/N) > ")
		_, err := fmt.Scanf("%s", &unz)
		if err != nil {
			fmt.Println("Wrong data")
			continue
		}
		switch {
		case unz == "Y" || unz == "y" || unz == "yes" || unz == "Yes":
			fmt.Println("OK")

			// where 7z
			binary, err := exec.LookPath("/usr/bin/7z")
			if err != nil {
				log.Fatalln(err)
			}

			// args
			args := []string{"7z", "e", cmds.Output}

			env := os.Environ()

			err = syscall.Exec(binary, args, env)
			if err != nil {
				log.Fatalln(err)
			}

		case unz == "N":
			fmt.Println("Finished scan and data grabber")
			os.Exit(0)
		default:
			fmt.Println("[!] Continuing, this might not be the correct statement? ")
			continue
		}
	}
}

func inject_jpg_zip(img_i, zip_file string, cmds *CmdLineOpts) {

	fileJpg := img_i
	fileZip := zip_file
	// Open original file
	firstFile, err := os.Open(fileJpg)
	che(err, "could not open image", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> File Opened and READ             \t", fileJpg)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Preping output as injected file  \t", opts.Output)
	defer firstFile.Close()
	// ZIP FILE
	secondFile, err := os.Open(fileZip)
	che(err, "could not open file", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> ZIP file has been opened         \t", opts.Input)
	defer secondFile.Close()
	// New file as output
	// use CMD's.OUTPUT as the output of the file name
	newFile, err := os.Create(cmds.Output)
	che(err, "could not create file", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> OUTPUT File with injection made  \t", opts.Output)
	defer newFile.Close()
	_, err = io.Copy(newFile, firstFile)
	che(err, "could not copy file", 1)
	_, err = io.Copy(newFile, secondFile)
	che(err, "could not copy file", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " ->  Finished Injection of image at  \t", formatDate, opts.Output)
	fmt.Println(BLU, "[INFO] WARNING: LOG: DATA: INFO: -> ", formatDate, "\t Going to attempt to locate the file, this will let you know that the data and file was for sure injected into the image :D ")
	fmt.Print("\n")
	fmt.Println(BLU, "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	call_finder(&opts)

}

// JPG and JPEG image walking
func walkFn(path string, f os.FileInfo, err error) error {
	for _, r := range regex_type_image {
		if r.MatchString(path) {
			fmt.Println("\033[31m[+] FOUND JPEG/JPG IMAGE ->  ", path, "\033[32m")
			// calling EXIF functions
			call_perl_s(path)
		}
	}
	return nil
}

func walk_without(path string, file os.FileInfo, err error) error {
	for _, r := range regex_type_image {
		if r.MatchString(path) {
			fmt.Println("[+] FOUND FILEPATH > ", path, "\033[31m")
		}
	}
	return nil
}

// walking dir
func walker_caller(opt *CmdLineOpts) {
	if err := filepath.Walk(opt.ZIPFP, walkFn); err != nil {
		log.Panicln(err)
	}
}

func jpg_1_test(img_i string, c *CmdLineOpts) {
	/*
		img := strings.Trim(c.Input, " ")
		re, _ := regexp.Compile(IMG_REG)
		if re.MatchString(img) {
			fmt.Println("[+] File -> ", c.Input, " Is a valid IMAGE format that is supported for this type of injection ")
		} else {
			fmt.Println(RED, "[!] This file -> ", c.Input, " Did not pass the regex file extension verification process, please check the file extension and try again")
		}

		Currently Searching for a regex string to verify the byte, and quite possibly as well might just switch to byte finding
	*/

	fileJpg := img_i

	// Zip signature is "\x50\x4b\x03\x04"
	file, err := os.Open(fileJpg)
	if err != nil {
		log.Fatal(err)
	}
	bufferedReader := bufio.NewReader(file)
	fileStat, _ := file.Stat()
	for i := int64(0); i < fileStat.Size(); i++ {
		myByte, err := bufferedReader.ReadByte()
		che(err, "Could not read buffer byte", 1)
		if myByte == '\x50' {
			byteSlice := make([]byte, 3)
			byteSlice, err = bufferedReader.Peek(3)
			che(err, "Could not read peak", 1)
			if bytes.Equal(byteSlice, []byte{'\x4b', '\x03', '\x04'}) {
				log.Printf("Found zip signature at byte %d.", i)
			}
		}
	}
	for {
		var unz string
		fmt.Print("Unzip it? (Y/N) > ")
		_, err := fmt.Scanf("%s", &unz)
		if err != nil {
			fmt.Println("Wrong data")
			continue
		}
		switch {
		case unz == "Y" || unz == "y" || unz == "yes" || unz == "Yes":
			fmt.Println("OK")

			// where 7z
			binary, err := exec.LookPath("/usr/bin/7z")
			if err != nil {
				log.Fatalln(err)
			}

			// args
			args := []string{"7z", "e", c.Input}

			env := os.Environ()

			err = syscall.Exec(binary, args, env)
			if err != nil {
				log.Fatalln(err)
			}

		case unz == "N":
			fmt.Println("Finished scan and data grabber")
			os.Exit(0)
		default:
			fmt.Println("[!] Continuing, this might not be the correct statement? ")
			continue
		}
	}

}

//ProcessImage is the wrapper to parse PNG bytes
func (mc *MetaChunk) ProcessImage(b *bytes.Reader, c *CmdLineOpts) {
	mc.validate(b)
	// this will be for second file reading
	// omitting again ArkAngeL43 -> Line 78
	// conversion !c.Encode
	if (c.Offset != "") && (!c.Encode && !c.Decode) {
		m.Chk.Data = []byte(c.Payload)
		m.Chk.Type = m.strToInt(c.Type)
		m.Chk.Size = m.createChunkSize()
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Print("\033[31m [INFO]   ", BLU, formatDate, "   -> Payload Original -> ", []byte(c.Payload), "\n")
		fmt.Print("\033[31m [INFO]   ", BLU, formatDate, "   -> Payload          -> ", m.Chk.Data, "\n")
		WriteData(b, c, bmb)
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> (NOTE: This will be a before and after Offset comparision)")
		var out string
		fmt.Print(RED, "[INFO] ", BLU, formatDate, RED, " -> Would you like to get the new IEND OFFSET (Y/n)> ")
		fmt.Scanf("%s", &out)
	}
	if (c.Offset != "") && c.Encode {
		m.Chk.Data = XorEncode([]byte(c.Payload), c.Key)
		m.Chk.Type = m.strToInt(c.Type)
		m.Chk.Size = m.createChunkSize()
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Printf("Payload Original: % X\n", []byte(c.Payload))
		fmt.Printf("Payload Encode: % X\n", m.Chk.Data)
		WriteData(b, c, bmb)
	}
	if (c.Offset != "") && c.Decode {
		offset, _ := strconv.ParseInt(c.Offset, 10, 64)
		b.Seek(offset, 0)
		m.readChunk(b)
		origData := m.Chk.Data
		m.Chk.Data = XorDecode(m.Chk.Data, c.Key)
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Printf("Payload Original: % X\n", origData)
		fmt.Printf("Payload Decode: % X\n", m.Chk.Data)
		WriteData(b, c, bmb)
	}
	if c.Meta {
		count := 1 //Start at 1 because 0 is reserved for magic byte
		// first start by asking the user if they would like to just locate the IEND or main
		// injection offset point
		scanner := bufio.NewReader(os.Stdin)
		fmt.Print("\nWould you like to locate just the IEND chunk? and injectable offset <y/n > ")
		fmt.Println("")
		fmt.Println(YEL, "\n[!] If you wanted to you can type -> chunk_finish to get all data chunks in the image as well")
		// bufio would not exactly work IO module gives EOF as a END OF INPUT to take in
		// 2022/02/12 02:06:11 EOF
		// exit status 1
		for {
			text, _ := scanner.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			if strings.Compare("y", text) == 0 {
				for chunkType != endChunkType {
					mc.getOffset(b)
					mc.readChunk(b)
					if mc.chunkTypeToString() == "IEND" {
						// we should probobly use a caller for this so- calling
						// func inter_change with print might be a good solution
						// ~ ArkAngeL43
						// got error upon changing
						//  [!] Error: Fatal:  Could not parse UINT ->  strconv.ParseUint: parsing "IEND": invalid syntax
						// so in order to fix this convert mc.offset to a INT64
						//mcm := fmt.Sprint(mc.Offset)
						// data using sprintf returns
						// 5526376 or 545368 where 1st INT64 is in the table and INT64 SECOND is outside the table
						// find way to output the hex of the offset, since its not displaying
						//output, err := strconv.ParseUint(hex_conv(mcm), 16, 64)
						//che(err, "Could not parse UINT -> ", 1)
						//fmt.Printf("[!] Chunk offset %#02x", mc.Offset)
						//
						// log: error solved, wasnt using right format string to parse
						// conv function not needed
						//
						data_mcm_hex := fmt.Sprintf("%#02x", mc.Offset)
						row_1 := []interface{}{mc.chunkTypeToString(), mc.Offset, data_mcm_hex}
						t := gotabulate.Create([][]interface{}{row_1})
						t.SetHeaders([]string{"Chunk Type", "Location Injectable OFFSET", "Injectable OFFSET HEX Translation"})
						t.SetEmptyString("None")
						t.SetAlign("right")
						fmt.Println("\n\033[32m Found IEND chunk -> \n", t.Render("grid"))
						fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> This data seems to be the actuall injectable point, would you like to hex dump the file to be sure this IEND tag is at the direct OFFSET of  -> ", mc.Offset)
						scanner := bufio.NewReader(os.Stdin)
						fmt.Println(YEL, "[INFO] ", BLU, formatDate, "Yes/NO > ")
						for {
							text, _ := scanner.ReadString('\n')
							// convert CRLF to LF
							text = strings.Replace(text, "\n", "", -1)
							if strings.Compare("Yes", text) == 0 || strings.Compare("YES", text) == 0 || strings.Compare("y", text) == 0 || strings.Compare("yes", text) == 0 {
								dumper(c.Input, 256)
							}
							if strings.Compare("n", text) == 0 || strings.Compare("No", text) == 0 || strings.Compare("NO", text) == 0 || strings.Compare("no", text) == 0 {
								fmt.Println("\n\nFinished Data skimmer in -> ", formatDate)
								os.Exit(0)
							}
							break
						}
					}
				}
			}
			if strings.Compare("n", text) == 0 || strings.Compare("chunk_finish", text) == 0 || strings.Compare("no", text) == 0 || strings.Compare("No", text) == 0 {
				for chunkType != endChunkType {
					mc.getOffset(b)
					mc.readChunk(b)
					// change to this was throwing everything into a data table, felt like it was better organized like
					offset_conf := fmt.Sprintf("%#02x", mc.Offset)
					chunk_ := mc.chunkTypeToString()
					counter := strconv.Itoa(count)
					crit := mc.checkCritType()
					chunk_len := strconv.Itoa(int(mc.Chk.Size))
					row_1 := []interface{}{offset_conf, chunk_, counter, crit, chunk_len}
					t := gotabulate.Create([][]interface{}{row_1})
					t.SetHeaders([]string{"Offset", "Chunk", "Chunk Number", "Chunk Importance", "Chunk Length"})
					t.SetEmptyString("None")
					t.SetAlign("right")
					fmt.Println("\033[31m\n", t.Render("grid"))

					//
					//fmt.Println("---- Chunk # " + strconv.Itoa(count) + " ----")
					//fmt.Printf("Chunk Offset: %#02x\n", mc.Offset)
					//fmt.Printf("Chunk Length: %s bytes\n", strconv.Itoa(int(mc.Chk.Size)))
					//fmt.Printf("Chunk Type: %s\n", mc.chunkTypeToString())
					//fmt.Printf("Chunk Importance: %s\n", mc.checkCritType())
					// omit to !c.Supress
					// ArkAngeL43 -> Change line 12
					if c.Suppress {
						fmt.Printf("Chunk Data: %s\n", "Suppressed")
					}
					fmt.Printf("\033[37mChunk CRC => %x\n", mc.Chk.CRC)
					chunkType = mc.chunkTypeToString()
					count++
				}
				break
			}
			// why?
			// Loop is terminated unconditionally
			// it works but why the warningS?
			break
		}

		fmt.Println("[+] Finished...")
	}
	// locating the offset
	// going to use standard flags for this
	// cant use STD flags so make it mandatory
	/*
		if *offset_yn {
			for chunkType != endChunkType {
				mc.getOffset(b)
				mc.readChunk(b)
				if mc.chunkTypeToString() == "IEND" {
					fmt.Println("found IEND chunk")
				} else {
					fmt.Println("nothing")
				}
			}
		}
	*/

}

func geo_loc(commds *CmdLineOpts) {
	f, err := os.Open(commds.Input)
	che(err, "Could not open file", 1)

	x, err := exif.Decode(f)
	che(err, "DEBUG: ERR: FATAL: during running the decode function for EXIF", 1)

	lat, long, err := x.LatLong()
	if err != nil {
		fmt.Fprintf(os.Stderr, "LatLong: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Fprintln(os.Stdout, f.Name())
		fmt.Println("[+] Image -> ", os.Args[0])
		fmt.Fprintf(os.Stdout, fmt.Sprintf("[+] lat:\t%v\n[+] long:\t%v", lat, long))
		fmt.Fprintf(os.Stdout, fmt.Sprintf("[+] Possible Location -> https://www.google.com/maps/@%v,%v", lat, long))
		fmt.Println("----------------------------------------------------------------------------------------------")
		fmt.Println("-> ++ > Generating MAP for geo location")
		geo_map("GEO_LOCATION_MAP#0", lat, long)
		os.Exit(0)
	}
}

// geo location map build
func geo_map(mapname string, lat, lon float64) {
	ctx := sm.NewContext()
	ctx.SetSize(600, 600)

	// get geotag from https://geocode-maps.yandex.ru )) - Москва, Тверская, 6
	// laty : 46.24130500044563
	// lony : 24.84987600049927
	ctx.AddObject(sm.NewMarker(s2.LatLngFromDegrees(lat, lon), color.RGBA{0xff, 0, 0, 0xff}, 16.0))
	// and Home
	//ctx.AddMarker(sm.NewMarker(s2.LatLngFromDegrees(55.919609, 37.742699), color.RGBA{0xff, 0, 0, 0xff}, 10.0))
	img, err := ctx.Render()
	che(err, "ERR: Context could not render", 1)
	if err := gg.SavePNG(mapname, img); err != nil {
		fmt.Println("could not save or create map")
		panic(err)
	}
}

func hex_dump(commandopt *CmdLineOpts) {
	// hex dump a file
	f, err := os.Open(commandopt.Input)
	che(err, "Could not open file", 1)
	defer f.Close()
	reader := bufio.NewReader(f)
	buf := make([]byte, 256)
	for {
		_, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		fmt.Printf("%s", hex.Dump(buf))
	}
}

// creating function to find file sig's
func file_sig(command_args *CmdLineOpts) {
	filename := command_args.Input
	for _, file := range filename {
		f, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "file: %v\n", err)
			continue
		}

		for _, val := range massSign {
			if strings.HasSuffix(filename, val.SuffixFile) || bytes.Contains(f, []byte(val.Sign)) {
				fmt.Print(CYN, "\n\n[INFO] DATA: ", BLU, formatDate, "\t", file, " Was possibly detected as -> ", RED, val.FileFormat, "\n\n")
				os.Exit(0)
			} else {
				fmt.Println(RED, "[INFO] DATA: ", BLU, formatDate, "\tSearching for suffix -> ", val.SuffixFile, " On sign -> ", val.Sign)
			}
		}
	}
}

func (mc *MetaChunk) marshalData() *bytes.Buffer {
	bytesMSB := new(bytes.Buffer)
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Size); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.CRC); err != nil {
		log.Fatal(err)
	}

	return bytesMSB
}

func (mc *MetaChunk) readChunk(b *bytes.Reader) {
	mc.readChunkSize(b)
	mc.readChunkType(b)
	mc.readChunkBytes(b, mc.Chk.Size)
	mc.readChunkCRC(b)
}

func (mc *MetaChunk) readChunkSize(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Size); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkType(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkBytes(b *bytes.Reader, cLen uint32) {
	mc.Chk.Data = make([]byte, cLen)
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkCRC(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.CRC); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) getOffset(b *bytes.Reader) {
	offset, _ := b.Seek(0, 1)
	mc.Offset = offset
}

func (mc *MetaChunk) chunkTypeToString() string {
	h := fmt.Sprintf("%x", mc.Chk.Type)
	decoded, _ := hex.DecodeString(h)
	result := fmt.Sprintf("%s", decoded)
	return result
}

func (mc *MetaChunk) checkCritType() string {
	fChar := string([]rune(mc.chunkTypeToString())[0])
	if fChar == strings.ToUpper(fChar) {
		return "Critical"
	}
	return "Ancillary"
}

func (mc *MetaChunk) validate(b *bytes.Reader) {
	var header Header

	if err := binary.Read(b, binary.BigEndian, &header.Header); err != nil {
		log.Fatal(err)
	}

	bArr := make([]byte, 8)
	binary.BigEndian.PutUint64(bArr, header.Header)

	if string(bArr[1:4]) != "PNG" {
		log.Fatal("Provided file is not a valid PNG format")
	} else {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> ", bArr[1:4], " Came back as a VALID HEADER")
	}
}

func (mc *MetaChunk) createChunkSize() uint32 {
	return uint32(len(mc.Chk.Data))
}

func (mc *MetaChunk) createChunkCRC() uint32 {
	bytesMSB := new(bytes.Buffer)
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
	return crc32.ChecksumIEEE(bytesMSB.Bytes())
}

func (mc *MetaChunk) strToInt(s string) uint32 {
	t := []byte(s)
	return binary.BigEndian.Uint32(t)
}

//
//
// third part with be the utils final part
//
///writer
func WriteData(r *bytes.Reader, c *CmdLineOpts, b []byte) {
	offset, err := strconv.ParseInt(c.Offset, 10, 64)
	che(err, "[!] Could not parse Integer to STRCONV during offset seeking", 1)
	// in later up's check if the file exists and if it does create a seperate function to create and inject a new file
	w, err := os.OpenFile(c.Output, os.O_RDWR|os.O_CREATE, 0777)
	che(err, "Could not read the file, this might be due to the fact the file doesnt exist D:", 1)
	r.Seek(0, 0)

	var buff = make([]byte, offset)
	r.Read(buff)
	w.Write(buff)
	w.Write(b)
	if c.Decode {
		r.Seek(int64(len(b)), 1) // right bitshift to overwrite encode chunk
		fmt.Println(RED, "[INFO]", BLU, formatDate, RED, " -> Found right bitshift")
	}
	_, err = io.Copy(w, r)
	if err == nil {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Success injecting, created file    \t", c.Output)
	}
	// now run a new exif data table
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Reading and dumping new file")
	call_perl_s(c.Output)
}

// reader
//PreProcessImage reads to buffer from file handle
func PreProcessImage(dat *os.File) (*bytes.Reader, error) {
	stats, err := dat.Stat()
	if err != nil {
		log.Fatal(err)
	}

	var size = stats.Size()
	b := make([]byte, size)

	bufR := bufio.NewReader(dat)
	if _, err := bufR.Read(b); err != nil {
		log.Fatal(err)
	}

	bReader := bytes.NewReader(b)

	return bReader, err
}

// encoder
func encodeDecode(input []byte, key string) []byte {
	var bArr = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		bArr[i] += input[i] ^ key[i%len(key)]
	}
	return bArr
}

//XorEncode returns encoded byte array
func XorEncode(decode []byte, key string) []byte {
	return encodeDecode(decode, key)
}

//XorDecode returns decoded byte array
func XorDecode(encode []byte, key string) []byte {
	return encodeDecode(encode, key)
}

// perl caller
func call_perl_s(image string) {

	prg := "perl"
	arg1 := "exif.pl"
	arg5 := "-f"
	arg2 := image
	cmd := exec.Command(prg, arg1, arg5, arg2)
	stdout, err := cmd.Output()
	che(err, "Could not run perl file -<> ", 1)
	fmt.Print(string(stdout))

}

// check if the image exists
func exists_(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// this is what was in the main file and where modification to the module happens

func init() {
	flags.StringVarP(&opts.Input, "input", "i", "", "Path to the original image file")
	flags.StringVarP(&opts.Output, "output", "o", "", "Path to output the new image file")
	flags.BoolVarP(&opts.Meta, "meta", "m", false, "Display the actual image meta details")
	flags.BoolVarP(&opts.Suppress, "suppress", "s", false, "Suppress the chunk hex data (can be large)")
	flags.StringVar(&opts.Offset, "offset", "", "The offset location to initiate data injection")
	flags.BoolVar(&opts.Inject, "inject", false, "Enable this to inject data at the offset location specified")
	flags.StringVar(&opts.Payload, "payload", "", "Payload is data that will be read as a byte stream")
	flags.StringVar(&opts.Type, "type", "rNDm", "Type is the name of the Chunk header to inject")
	flags.StringVar(&opts.Key, "key", "", "The enryption key for payload")
	flags.BoolVar(&opts.Encode, "encode", false, "XOR encode the payload")
	flags.BoolVar(&opts.Decode, "decode", false, "XOR decode the payload")
	// JPG Support for EXIF, and ZIP extraction
	flags.BoolVar(&opts.Extract_ZIP, "JPGEXTRACT", false, "Scan for ZIP files and extract them from images | JPEG FORMAT ONLY")
	// INJECT ZIP files into JPG/JPEG files
	flags.BoolVar(&opts.INJECT_ZIP, "JPGINJECT", false, " Start / Activate ZIP file injection")
	flags.StringVar(&opts.ZIPFP, "filepath", "", "path to the ZIP FILE")
	// hex dumping of files
	flags.BoolVar(&opts.hexdump, "hexd", false, "Hex dump a image")
	// geo locations
	flags.BoolVar(&opts.geo, "geo", false, "Get the GEO location of a JPG/JPEG Info, of which has GPS location ")
	// walking filepaths for JPEG and scanning for embedded ZIP files
	flags.BoolVar(&opts.walk, "walk", false, "Walk a filepath for images and EXIF dump all data to all images")
	// regular walk for filepaths
	flags.BoolVar(&opts.walkerfp, "walkf", false, "Walk a filepath for images")
	// set for unknown file finding / discovery
	flags.BoolVar(&opts.discover, "discover", false, "Determin the type of file of an unknown file")
	flags.Lookup("type").NoOptDefVal = "rNDm"
	flags.Usage = usage
	flags.Parse(os.Args[1:])

	if flags.NFlag() == 0 {
		banner_m("txt/red.txt", clear_hex, RED)
		flags.PrintDefaults()
		os.Exit(1)
	}
	if opts.Offset != "" {
		byteOffset, _ := strconv.ParseInt(opts.Offset, 0, 64)
		opts.Offset = strconv.FormatInt(byteOffset, 10)
	}
	// should omit comparision to bool constant, modified and simplified to !opts.Meta
	// ArkAngeL43
	if opts.Suppress && (!opts.Meta) {
		log.Fatal("Fatal: The --meta flag is required when using --suppress")
	}
	if opts.Meta && (opts.Offset != "") {
		log.Fatal("Fatal: The --meta flag is mutually exclusive with --offset")
	}
	if opts.Inject && (opts.Offset == "") {
		log.Fatal("Fatal: The --offset flag is required when using --inject")
	}
	if opts.Inject && (opts.Payload == "") {
		log.Fatal("Fatal: The --payload flag is required when using --inject")
	}
	if opts.Inject && opts.Key == "" {
		fmt.Println("Warning: No key provided. Payload will not be encrypted")
	}
	if opts.Encode && opts.Key == "" {
		log.Fatal("Fatal: The --encode flag requires a --key value")
	}
	// opts for JPEG and JPG injection / EXTRACTION
	if opts.INJECT_ZIP && opts.ZIPFP == "" && opts.Output == "" {
		log.Fatal("the --JPGINJECT requires the --filepath flag to specify the zip files as well as the -o flag to specify a file or image output name | EXAMPLE BELOW \n\n")
		log.Fatal("| -> +++++? | go run main.go -i image.jpg -o main.jpg --JPGINJECT --filepath file.zip")
	}
}

func usage() {
	banner_m("txt/red.txt", clear_hex, RED)
	fmt.Fprintf(os.Stderr, "Example Usage: %s -i in.png -o out.png --inject --offset 0x85258 --payload 1234\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Encode Usage: %s -i in.png -o encode.png --inject --offset 0x85258 --payload 1234 --encode --key secret\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Decode Usage: %s -i encode.png -o decode.png --offset 0x85258 --decode --key secret\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Flags: %s {OPTION]...\n", os.Args[0])
	flags.PrintDefaults()
	os.Exit(0)
}

// banner
func banner_m(bannerf, clear_, color string) {
	fmt.Println(clear_)
	content, err := ioutil.ReadFile(bannerf)
	che(err, "Could not open banner file got error -> ", 1)
	fmt.Println(color, string(content))
}

func main() {
	banner_m(banner, clear_hex, BLU)
	if opts.walk {
		walker_caller(&opts)
		os.Exit(0)
	}
	if opts.walkerfp {
		if err := filepath.Walk(opts.ZIPFP, walk_without); err != nil {
			log.Panicln(err)
		}
		os.Exit(0)
	}
	if opts.discover {
		file_sig(&opts)
		os.Exit(0)
	}
	if exists_(opts.Input) {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> File Exists \t", opts.Input)
	} else {
		fmt.Println(RED, "[!] WARN: FILE  -> ", BLU, formatDate, opts.Input, " \tDOES NOT EXIST")
	}
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Opening file   \t", opts.Input)
	dat, err := os.Open(opts.Input)
	// check err, got warning on checking error before defer
	che(err, "Could not open file? Got err -> ", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> ", opts.Input, "\t Successfully opened")
	defer dat.Close()
	call_perl_s(opts.Input)
	// if VALID JPEG, then move on with possible injection or EXTRACTION processes
	if opts.Extract_ZIP {
		jpg_1_test(opts.Input, &opts)
		fmt.Println("done")
		os.Exit(0)
	}
	if opts.INJECT_ZIP {
		inject_jpg_zip(opts.Input, opts.ZIPFP, &opts)
		fmt.Println(" finished ")
		os.Exit(0)
	}
	if opts.hexdump {
		hex_dump(&opts)
		os.Exit(0)
	}
	if opts.geo {
		geo_loc(&opts)
		os.Exit(0)
	}
	bReader, err := PreProcessImage(dat)
	che(err, " Could not process image got err -> ", 1)
	IMG_png.ProcessImage(bReader, &opts)
}
