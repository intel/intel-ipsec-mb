#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2025, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************
"""

"""
Assembly source code formatter.

This script formats assembly source files by:
- Converting tabs to spaces or spaces to tabs
- Removing trailing whitespace
- Applying consistent indentation rules based on alignment value
"""

import argparse
import sys
import os


def calculate_aligned_column(current_col, align_value):
    """
    Calculate the nearest column that's a multiple of align_value.

    Args:
        current_col (int): Current column position (0-based)
        align_value (int): Alignment value (e.g., 8 for 8-space alignment)

    Returns:
        int: The aligned column position
    """
    # Find the nearest column where column % align_value == 0
    if current_col % align_value == 0:
        return current_col

    # Calculate the previous and next alignment boundaries
    prev_boundary = (current_col // align_value) * align_value
    next_boundary = prev_boundary + align_value

    # Choose the nearest boundary, preferring forward movement when distances are equal
    if (current_col - prev_boundary) < (next_boundary - current_col):
        return prev_boundary
    else:
        return next_boundary


def format_line(line, align_value, use_tabs=False):
    """
    Format a single line according to the formatting rules.

    Args:
        line (str): The input line
        align_value (int): Alignment value for indentation
        use_tabs (bool): Whether to use tabs instead of spaces

    Returns:
        str: The formatted line
    """
    # Remove trailing whitespace
    line = line.rstrip()

    # Handle empty lines
    if not line or line.isspace():
        return ""

    # Split line into code and comment parts
    comment_index = line.find(";")
    if comment_index != -1:
        code_part = line[:comment_index]
        comment_part = line[comment_index:]  # includes the ';' character
    else:
        code_part = line
        comment_part = ""

    # Expand all tabs to spaces in the code part using the align_value as tab width
    expanded_code = code_part.expandtabs(align_value)

    # Find the first non-whitespace character in the expanded code
    first_non_space_index = 0
    for i, char in enumerate(expanded_code):
        if not char.isspace():
            first_non_space_index = i
            break
    else:
        # Code part contains only whitespace, but there might be a comment
        if comment_part:
            # Comment-only line - need to align the comment properly
            # Find the original position of the comment (before expansion)
            original_comment_pos = 0
            for i, char in enumerate(line):
                if char == ";":
                    original_comment_pos = i
                    break

            # Calculate visual column position considering tabs
            visual_col = 0
            for char in line[:original_comment_pos]:
                if char == "\t":
                    visual_col = ((visual_col // align_value) + 1) * align_value
                else:
                    visual_col += 1

            # Calculate aligned column for the comment
            aligned_col = calculate_aligned_column(visual_col, align_value)

            # Create proper indentation for the comment
            if use_tabs:
                tab_count = aligned_col // align_value
                remaining_spaces = aligned_col % align_value
                indentation = "\t" * tab_count + " " * remaining_spaces
            else:
                indentation = " " * aligned_col

            return indentation + comment_part
        else:
            return ""

    # Calculate the aligned column for the first non-whitespace character
    aligned_col = calculate_aligned_column(first_non_space_index, align_value)

    # Extract the content (non-whitespace part of code)
    content = expanded_code[first_non_space_index:]

    # Create the new indentation
    if use_tabs:
        # Calculate how many tabs we need for indentation
        tab_count = aligned_col // align_value
        remaining_spaces = aligned_col % align_value
        indentation = "\t" * tab_count + " " * remaining_spaces

        # Convert sequences of spaces in code content to tabs
        content = convert_spaces_to_tabs(content, align_value)
    else:
        indentation = " " * aligned_col

    # Combine indentation, formatted code content, and comment
    result = indentation + content
    if comment_part:
        # Add the comment part (already includes trailing whitespace removal)
        result += comment_part

    return result


def convert_spaces_to_tabs(text, align_value):
    """
    Convert sequences of multiple spaces to tabs.
    Single spaces between words are left unchanged.
    For 2+ spaces, remove all spaces and insert tabs to reach the nearest align column.

    Args:
        text (str): The text to convert
        align_value (int): Number of spaces that equal one tab

    Returns:
        str: Text with space sequences converted to tabs
    """

    # We need to process the text character by character to track column positions
    result = []
    i = 0
    current_col = 0

    while i < len(text):
        if text[i] == " ":
            # Count consecutive spaces
            space_count = 0
            while i < len(text) and text[i] == " ":
                space_count += 1
                i += 1

            if space_count == 1:
                # Single space - keep as is
                result.append(" ")
                current_col += 1
            else:
                # Multiple spaces - convert to tabs
                # Calculate the target column (round up to nearest align boundary)
                target_col = current_col + space_count
                aligned_target = ((target_col + align_value - 1) // align_value) * align_value

                # Calculate how many tabs we need (minimum 1 for multiple spaces)
                tabs_needed = max(1, (aligned_target - current_col) // align_value)
                result.append("\t" * tabs_needed)
                current_col = current_col + (tabs_needed * align_value)
        else:
            # Regular character
            result.append(text[i])
            current_col += 1
            i += 1

    return "".join(result)


def format_file_content(content, align_value, use_tabs=False):
    """
    Format the entire file content.

    Args:
        content (str): The file content
        align_value (int): Alignment value for indentation
        use_tabs (bool): Whether to use tabs instead of spaces

    Returns:
        tuple: (formatted_content, has_changes) where has_changes is True if formatting was needed
    """
    # Check if original content ended with a newline
    ends_with_newline = content.endswith("\n") or content.endswith("\r\n")

    lines = content.splitlines()
    formatted_lines = []
    has_changes = False

    for line in lines:
        formatted_line = format_line(line, align_value, use_tabs)
        formatted_lines.append(formatted_line)

        # Check if this line was changed
        if line.rstrip() != formatted_line:
            has_changes = True

    # Join lines back together
    formatted_content = "\n".join(formatted_lines)

    # Always ensure the file ends with a newline
    if formatted_content and not formatted_content.endswith("\n"):
        formatted_content += "\n"
        # If original didn't end with newline but we're adding one, that's a change
        if not ends_with_newline:
            has_changes = True
    elif not formatted_content:
        # Empty file should remain empty (no newline)
        pass

    return formatted_content, has_changes


def format_assembly_file(filepath, align_value, use_tabs=False, in_place=False, silent=False):
    """
    Format a single assembly file.

    Args:
        filepath (str): Path to the file to format
        align_value (int): Alignment value for indentation
        use_tabs (bool): Whether to use tabs instead of spaces
        in_place (bool): Whether to modify the file in place
        silent (bool): Whether to suppress output

    Returns:
        tuple: (success, has_changes) where success is True if no errors occurred,
               and has_changes is True if formatting was needed
    """
    try:
        # Read the file
        with open(filepath, "r", encoding="utf-8") as f:
            original_content = f.read()

        # Format the content
        formatted_content, has_changes = format_file_content(
            original_content, align_value, use_tabs
        )

        if in_place:
            # Write back to the original file
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(formatted_content)
            if not silent:
                print(f"Formatted: {filepath}")
        else:
            # Print to stdout (unless silent)
            if not silent:
                print(formatted_content)

        return True, has_changes

    except Exception as e:
        if not silent:
            print(f"Error processing {filepath}: {e}", file=sys.stderr)
        return False, False


def main():
    """Main entry point of the script."""
    parser = argparse.ArgumentParser(
        description="Format x86 assembly source files with consistent indentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s file.asm                     # Check formatting (exit 1 if changes needed)
  %(prog)s --align 4 file.asm           # Check with 4-space alignment
  %(prog)s --tabs file.asm              # Check using tabs instead of spaces
  %(prog)s --format-in-place file.asm   # Format file in place (exit 0 if no changes needed)
  %(prog)s --silent *.asm               # Format multiple files silently
  %(prog)s --silent file.asm            # Check formatting silently (exit code only)
        """,
    )

    parser.add_argument("files", nargs="+", help="Assembly source files to format")

    parser.add_argument(
        "-a", "--align", type=int, default=8, help="Alignment value for indentation (default: 8)"
    )

    parser.add_argument(
        "-t", "--tabs", action="store_true", help="Use tabs instead of spaces for indentation"
    )

    parser.add_argument(
        "-i",
        "--format-in-place",
        action="store_true",
        help="Modify files in place instead of printing to stdout",
    )

    parser.add_argument("-s", "--silent", action="store_true", help="Suppress output messages")

    args = parser.parse_args()

    # Validate alignment value
    if args.align <= 0:
        if not args.silent:
            print("Error: Alignment value must be positive", file=sys.stderr)
        return 1

    # Process each file
    success_count = 0
    total_files = len(args.files)
    files_with_changes = 0

    for filepath in args.files:
        if not os.path.exists(filepath):
            if not args.silent:
                print(f"Error: File not found: {filepath}", file=sys.stderr)
            continue

        if not os.path.isfile(filepath):
            if not args.silent:
                print(f"Error: Not a file: {filepath}", file=sys.stderr)
            continue

        success, has_changes = format_assembly_file(
            filepath, args.align, args.tabs, args.format_in_place, args.silent
        )

        if success:
            success_count += 1
            if has_changes:
                files_with_changes += 1

    # Print summary if processing multiple files and not silent
    if total_files > 1 and args.format_in_place and not args.silent:
        print(f"Successfully formatted {success_count} out of {total_files} files")

    # Return exit codes based on mode
    if args.format_in_place:
        # In --format-in-place mode, return 0 if all files processed successfully
        return 0 if success_count == total_files else 1
    else:
        # When not in --format-in-place mode, return 1 if any file had formatting issues
        return 1 if files_with_changes > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
