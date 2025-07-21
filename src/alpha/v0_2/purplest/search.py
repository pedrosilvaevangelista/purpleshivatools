#!/usr/bin/env python3
import sys
import tty
import termios
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.live import Live

console = Console()

def search_tools(tool_manager, search_term, per_page, current_page_ref):
    """Search tools and allow selection with arrow keys using raw terminal input"""
    matches = tool_manager.find_tools(search_term)
    if not matches:
        console.print(f"[red]No tools found matching '{search_term}'[/red]")
        time.sleep(1)
        return False
    
    selected_index = 0
    total_matches = len(matches)
    
    def generate_search_display():
        """Generate the search results display"""
        table = Table(
            title=f"Search Results for '{search_term}' ({total_matches} found)",
            title_style="bold purple",
            box=box.ROUNDED,
            show_header=True,
            border_style="purple",
            padding=(0, 1),
            expand=True
        )
        table.add_column("", width=2, style="bold green")
        table.add_column("Tool Name", style="bold")
        table.add_column("Category", style="red")
        table.add_column("Description", style="dim")
        
        for idx, tool in enumerate(matches):
            marker = "►" if idx == selected_index else " "
            name_style = "bold green" if idx == selected_index else "white"
            table.add_row(
                marker,
                f"[{name_style}]{tool['name']}[/{name_style}]",
                tool['category'],
                tool.get('description', 'No description available')[:50] + "..." if len(tool.get('description', '')) > 50 else tool.get('description', 'No description available')
            )
        
        instructions = "[bold blue]Controls:[/bold blue] ↑/↓ Navigate • Enter: Select • q/Esc: Cancel"
        
        panel = Panel(
            table,
            title="[bold purple]🔍 TOOL SEARCH[/bold purple]",
            subtitle=instructions,
            border_style="purple",
            padding=(1, 2)
        )
        return panel
    
    def get_single_char():
        """Get a single character from stdin without pressing enter"""
        if sys.platform == 'win32':
            import msvcrt
            return msvcrt.getch().decode('utf-8', errors='ignore')
        else:
            # Unix/Linux/macOS
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                char = sys.stdin.read(1)
                return char
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def handle_arrow_keys(first_char):
        """Handle arrow key sequences"""
        if first_char == '\x1b':  # ESC sequence
            try:
                # Try to read the next characters for arrow keys
                if sys.platform != 'win32':
                    second = sys.stdin.read(1)
                    if second == '[':
                        third = sys.stdin.read(1)
                        if third == 'A':
                            return 'up'
                        elif third == 'B':
                            return 'down'
                        elif third == 'C':
                            return 'right'
                        elif third == 'D':
                            return 'left'
                return 'escape'
            except:
                return 'escape'
        return first_char
    
    tool_selected = False
    
    try:
        # Use Live display for smooth updates
        with Live(generate_search_display(), console=console, auto_refresh=False) as live:
            while True:
                try:
                    # Get input character
                    char = get_single_char()
                    
                    # Handle different input types
                    if char == '\x1b':  # Escape sequence (might be arrow key)
                        key = handle_arrow_keys(char)
                        
                        if key == 'up':
                            selected_index = max(0, selected_index - 1)
                            live.update(generate_search_display(), refresh=True)
                        elif key == 'down':
                            selected_index = min(total_matches - 1, selected_index + 1)
                            live.update(generate_search_display(), refresh=True)
                        elif key == 'escape':
                            break
                    
                    elif char == '\r' or char == '\n':  # Enter key
                        selected_tool = matches[selected_index]
                        
                        # Attempt selection
                        if tool_manager.select_tool(selected_tool['index']):
                            current_page_ref[0] = (selected_tool['index'] // per_page) + 1
                            tool_selected = True
                            break
                        else:
                            # Show error temporarily
                            error_table = Table.grid()
                            error_table.add_row(f"[red]✗ Failed to select tool {selected_tool['name']}[/red]")
                            error_table.add_row("")
                            error_table.add_row(generate_search_display())
                            live.update(error_table, refresh=True)
                            time.sleep(1)
                            live.update(generate_search_display(), refresh=True)
                    
                    elif char.lower() == 'q':  # Quit
                        break
                    
                    elif char == '\x03':  # Ctrl+C
                        break
                    
                    # Ignore other characters
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    console.print(f"[red]Input error: {str(e)}[/red]")
                    time.sleep(1)
                    break
                    
    except Exception as e:
        console.print(f"[red]Display error: {str(e)}[/red]")
        return False
    
    return tool_selected


# Alternative approach using Rich's built-in prompt system
def search_tools_simple(tool_manager, search_term, per_page, current_page_ref):
    """Simpler approach using Rich prompts - fallback if the above doesn't work"""
    matches = tool_manager.find_tools(search_term)
    if not matches:
        console.print(f"[red]No tools found matching '{search_term}'[/red]")
        return False
    
    # Display all matches
    table = Table(
        title=f"Search Results for '{search_term}'",
        title_style="bold purple",
        box=box.ROUNDED,
        show_header=True,
        border_style="purple"
    )
    table.add_column("Index", style="bold blue", width=6)
    table.add_column("Tool Name", style="bold green")
    table.add_column("Category", style="red")
    table.add_column("Description", style="dim")
    
    for idx, tool in enumerate(matches):
        table.add_row(
            str(idx + 1),
            tool['name'],
            tool['category'],
            tool.get('description', 'No description available')[:60] + "..." if len(tool.get('description', '')) > 60 else tool.get('description', 'No description available')
        )
    
    console.print(table)
    
    # Simple number-based selection
    try:
        from rich.prompt import IntPrompt
        choice = IntPrompt.ask(
            f"Select tool (1-{len(matches)}) or 0 to cancel",
            default=0,
            show_default=True
        )
        
        if choice == 0 or choice > len(matches):
            return False
            
        selected_tool = matches[choice - 1]
        
        if tool_manager.select_tool(selected_tool['index']):
            current_page_ref[0] = (selected_tool['index'] // per_page) + 1
            return True
        else:
            console.print(f"[red]✗ Failed to select tool {selected_tool['name']}[/red]")
            return False
            
    except KeyboardInterrupt:
        return False
    except Exception as e:
        console.print(f"[red]Selection error: {str(e)}[/red]")
        return False