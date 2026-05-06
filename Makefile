CC = gcc
CFLAGS = -Wall -Wextra -I./include -O2
LDFLAGS = -lpcap

# Project directories
SRCDIR = src
OBJDIR = obj
INCDIR = include

# Source and Object files
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

# Executable name
EXEC = packet_analyzer

.PHONY: all clean dirs

all: dirs $(EXEC)

dirs:
	@mkdir -p $(OBJDIR)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "=================================================="
	@echo "Build successful!"
	@echo "Run the analyzer with root privileges:"
	@echo "sudo ./$(EXEC) <interface> [BPF expression]"
	@echo "Example: sudo ./$(EXEC) eth0 'tcp port 80'"
	@echo "=================================================="

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJDIR) $(EXEC)
	@echo "Cleaned build files."
