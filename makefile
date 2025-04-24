# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

# Directories
OBJDIR = objects
BINDIR = programs

# Programs and their sources
PROGRAMS = receiver sender prime sign verify

receiver_SRCS = receiver.c elgamal_encrypt.c elgamal_utils.c key_io.c data_io.c
sender_SRCS   = sender.c elgamal_encrypt.c elgamal_utils.c key_io.c data_io.c
prime_SRCS    = prime.c elgamal_utils.c
signature_SRCS = sign.c elgamal_signature.c elgamal_utils.c key_io.c
verify_SRCS  = verify.c elgamal_signature.c elgamal_utils.c key_io.c

receiver_OBJS = $(receiver_SRCS:%.c=$(OBJDIR)/%.o)
sender_OBJS   = $(sender_SRCS:%.c=$(OBJDIR)/%.o)
prime_OBJS    = $(prime_SRCS:%.c=$(OBJDIR)/%.o)
signature_OBJS = $(signature_SRCS:%.c=$(OBJDIR)/%.o)
verify_OBJS  = $(verify_SRCS:%.c=$(OBJDIR)/%.o)

# Default target builds all programs
all: $(PROGRAMS:%=$(BINDIR)/%)

# Rule to link each target
$(BINDIR)/receiver: $(receiver_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BINDIR)/sender: $(sender_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BINDIR)/prime: $(prime_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BINDIR)/sign: $(signature_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BINDIR)/verify: $(verify_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

# Rule to compile .c into objects/%.o
$(OBJDIR)/%.o: %.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -rf $(OBJDIR) $(BINDIR)

.PHONY: all clean