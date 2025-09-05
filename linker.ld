SECTIONS
{
    .text :
    {
        KEEP(*(.text.start))
        *(.text*)
    }
}
