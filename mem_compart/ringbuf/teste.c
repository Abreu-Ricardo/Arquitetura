#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

void update_message(const char *format, ...) {
    // Move cursor to beginning of line
    printf("\r");
    
    // Clear the line
    printf("\033[2K");
    
    // Print the message
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    // Flush the buffer to ensure immediate display
    fflush(stdout);
}

int main() {
    int i;

    for (i = 0; i <= 100; i++) {
        update_message("Contador: %d%%", i);
        usleep(50000);  // Small delay to see the effect
    }
    printf("\n");  // Move to new line at the end
    return 0;
}
