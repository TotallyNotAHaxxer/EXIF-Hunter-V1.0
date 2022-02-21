```
                                    _______ _     _ _____ _______     _     _ _     _ __   _ _______ _______  ______
                                    |______  \___/    |   |______ ___ |_____| |     | | \  |    |    |______ |_____/
                                    |______ _/   \_ __|__ |           |     | |_____| |  \_|    |    |______ |    \_
                                    Image injection and Forensics Command Line Software for PNG and JPG image/file formats 
                                    -------------------------------------------------------------------------------------
```

# What is this program?

This is a simple program written and based off the black hat go module for image injection accept turned into more options and a bit more improoved / tidied up for a information based module, EXIF hunter can do all of the following 

<br>


> Inject PNG images 

> Grab EXIF data from all image formats 

> Grab Offset's, chunks, crc, chunk types, etc from PNG images

> encode injection payloads for PNG image formats 

> decode injected data and payloads for PNG image formats

> hex dump files and images 

> specify chunks to inject PNG images with 

> Inject ZIP files into JPG/JPEG image formats

> Extract hidden ZIP files inside of JPG/JPEG image formats

> Grab and map the GEO location of a JPG/JPEG image 

> Walk Filepaths for all files matching image names ( jpg, jpeg, png, gif etc )

> Discover unknown file types

> Scrape and dump all EXIF data of every image or file inside of a directory that matches titles of JPG, PNG, JPEG etc 

and some more if you dig into it and get used to the program itself

# Example HELP menu to activate this run the file with no args

```

                         _______ ___ ___ _______ _______                  _______               __              
                        |    ___|   |   |_     _|    ___|     ______     |   |   |.--.--.-----.|  |_.-----.----.
                        |    ___|-     -|_|   |_|    ___|    |______|    |       ||  |  |     ||   _|  -__|   _|
                        |_______|___|___|_______|___|                    |___|___||_____|__|__||____|_____|__|
                        Image injection and Forensics Command Line Software for PNG and JPG image/file formats 
                        -------------------------------------------------------------------------------------
                        Author -> ArkAngeL43
                        Github -> https://github.com/ArkAngeL43
                        ------
                             |> Help menu

                        ------
                             |> Flags
                                   |
                                   |++>
                                   ____________________________________________________________________________________________________CSTAT__
                                    -o or --output  | Specify the output image after injection                                       | Active | 
                                    -i or --input   | Specify the input image for injection, metadata, etc                           | Active | 
                                    --inject        | Inject data into a PNG image                                                   | Active | 
                                    --offset        | Usable with --inject, this is the offset to inject data into                   | Active | 
                                    --meta          | Grab meta data of the image such as EXIF and OFFSET locations                  | Active | 
                                    --JPGINJECT     | Inject ZIP files or files into JPG/JPEG Images formats                         | Active | 
                                    --JPGEXTRACT    | Extract ZIP files from JPEG/JPG Image formats                                  | Active |
                                    --help or -h    | Run this help menu                                                             | Active | 
                                    --encode        | XOR Encode the payload to inject into PNG images                               | Active | 
                                    --decode        | XOR Decode the payload to inject into PNG images                               | Active | 
                                    --key           | The encryption key for the payload                                             | Active | 
                                    --suppress      | Suppress the chunk hex data which can be large                                 | Active | 
                                    --hexd          | Hex dump an image or file                                                      | Active | 
                                    --geo           | Trace the GEO-GPS Tags to a location in JPG image formats                      | Active | 
                                    --filepath      | Specify the ZIP to inject into JPG/JPEG image formats                          | Active | 
                                    --walkf         | Fast scan linux root filesystems for JPEG images that possibly have ZIP files  | Active |
                                    --discover      | Discover what filetype a file is that is seen as `unknown`                     | Active |
                                    --type          | Type is the name of the Chunk header to inject (DEFUALT: rNDm)                 | Active |  
                                   ------------------------------------------------------------------------------------------------------------
                              |> Example Usages
                                        |
                                        |+++>|
                                        _______________________________________________________________________________________________________
                                        | go run main.go -i img/main.png --meta                                           | Grabs the metadata on the image
                                        | go run main.go -i img/main.png -o j.png --inject --offset 0x85258 --data 13234  | Injects data into an image
                                        | go run main.go -i img/example.jpg --geo                                         | Gets GEO Location of image
                                        | go run main.go -i unknown_filename --discover                                   | Will try to identify files without extensions
                                        | go run main.go --filepath / --walkf                                             | Walk the filepath for image files
                                        | go run main.go -i bety.jpg --hexd                                               | Hex dump an image or file
                                        | go run main.go -i bety.jpg -o bety_injected.jpg --JPGINJECT --filepath main.zip | Inject a ZIP file into a JPG image 
                                        | go run main.go -i img/injected_zip.jpg --JPGEXTRACT                             | Scan and extract ZIP files from JPG images
                                        | >>>>++++                                                                        ]
                                        | go run main.go -i in.png -o encode.png --inject --offset 0x85258 --payload 1234 | Will inject a PNG image with a encoded payload
                                        | --encode --key secret                                                           | WITH secret keys                                   
                                        | >>>>++++                                                                        ]
                                        | go run main.go -i encode.png -o decode.png --offset 0x85258                     | Will decode a messgae or injected data set
                                        | --decode --key secret                                                           | With a certian key to decode
                                        |                                                                                 |
                                        | go run main.go --filepath / --walk                                              | Will dump ALL EXIF DATA ON EVERY FILEPATH 
                                        | AND FILE LABELED JPEG, JPG, PNG, PG, GIF, ETC within a specified filepath       |
                                        |
                                        | 
                    
                                                                                                            

```

# Example output of uding the --meta tag with a PNG file

```

=== EXIF Table ===
┌─────────────╥───────────────────┬─────────────────────────┐
│ Data Number ║ Data              │After DATA EXIF          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Filter             │        Adaptive         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileInodeChangeDate│2022:02:09 17:17:57-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileTypeExtension  │           png           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageSize          │        3840x1920        │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileType           │           PNG           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║MIMEType           │        image/png        │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║BitDepth           │            8            │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ExifToolVersion    │          12.30          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║SignificantBits    │          8 8 8          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileName           │        term.png         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageHeight        │          1920           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Compression        │     Deflate/Inflate     │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileSize           │         534 KiB         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Interlace          │      Noninterlaced      │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Megapixels         │           7.4           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileAccessDate     │2022:02:09 17:17:57-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FilePermissions    │       -rw-r--r--        │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ColorType          │           RGB           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileModifyDate     │2022:02:09 17:17:55-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Software           │     mate-screenshot     │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageWidth         │          3840           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Directory          │ /home/reaper/Downloads  │
└─────────────╨───────────────────┴─────────────────────────┘
=== END of EXIF Table === 


 [INFO]   13:03:12   ->  [80 78 71]  Came back as a VALID HEADER
Would you like to locate just the IEND chunk? and injectable offset <y/n > 
 
[!] If you wanted to you can type -> chunk_finish to get all data chunks in the image as well
y

 Found IEND chunk -> 
 +---------------+-------------------------------+--------------------------------------+
|    Chunk Type |    Location Injectable OFFSET |    Injectable OFFSET HEX Translation |
+===============+===============================+======================================+
|          IEND |                        546910 |                              0x8585e |
+---------------+-------------------------------+--------------------------------------+

 [INFO]   13:03:33   -> This data seems to be the actuall injectable point, would you like to hex dump the file to be sure this IEND tag is at the direct OFFSET of  ->  546910
 [INFO]   13:03:33 Yes/NO > 

```

# tracing JPEG GPS location in the images while creating a map image of the cordinants

```

```

