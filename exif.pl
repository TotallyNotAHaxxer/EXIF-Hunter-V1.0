# exif for png file

use strict;
use warnings;
use Getopt::Std;
use feature 'say';
use Term::ANSIColor;
use Image::ExifTool;
use utf8;
use Text::Table ();



my %opts = (
    f => '',                   
);

# f = file
getopt('f:', \%opts);

# exif decleration 
my $exif = new Image::ExifTool;
my $info = $exif->ImageInfo($opts{f});
binmode STDOUT, ':encoding(utf8)';


sub file_exif_table() {
    my @cols = qw/Data/;
    push @cols,
        +{
        title => "After DATA EXIF",
        align => "center",
        };
    my $sep = \'│';
    
    my $major_sep = \'║';
    my $tb        = Text::Table->new( $sep, " Data Number ", $major_sep,
        ( map { +( ( ref($_) ? $_ : " $_ " ), $sep ) } @cols ) );
    
    my $num_cols = @cols;

    # load table 
    foreach (keys %$info) {
        $tb->load( [1, $_,    $$info{$_}] );
        #print "\033[37m[ \033[34mEXIT DATA \033[37m] \033[32m $_ => $$info{$_}\n";
    }


    my $make_rule = sub {
        my ($args) = @_;
    
        my $left      = $args->{left};
        my $right     = $args->{right};
        my $main_left = $args->{main_left};
        my $middle    = $args->{middle};
    
        return $tb->rule(
            sub {
                my ( $index, $len ) = @_;
    
                return ( '─' x $len );
            },
            sub {
                my ( $index, $len ) = @_;
    
                my $char = (
                    ( $index == 0 )             ? $left
                    : ( $index == 1 )             ? $main_left
                    : ( $index == $num_cols + 1 ) ? $right
                    :                               $middle
                );
    
                return $char x $len;
            },
        );
    };
    
    # ASCII TC LOAD FLOOR
    my $start_rule = $make_rule->(
        {
            left      => '┌',
            main_left => '╥',
            right     => '┐',
            middle    => '┬',
        }
    );
    
    # ASCII TC LOAD CENTER
    my $mid_rule = $make_rule->(
        {
            left      => '├',
            main_left => '╫',
            right     => '┤',
            middle    => '┼',
        }
    );
    
    # ASCII TC LOAD ROOF
    my $end_rule = $make_rule->(
        {
            left      => '└',
            main_left => '╨',
            right     => '┘',
            middle    => '┴',
        }
    );
    print "\n\033[37m=== EXIF Table ===\n", $start_rule, $tb->title,( map { $mid_rule, $_, } $tb->body() ), $end_rule;
    print "=== END of EXIF Table === \n\n\n"
}

file_exif_table();