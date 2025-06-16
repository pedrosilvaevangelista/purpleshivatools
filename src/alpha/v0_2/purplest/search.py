#!/usr/bin/env python3
import time
import queue
import keyboard
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.live import Live

console = Console()

def search_tools(tool_manager, search_term, per_page, current_page_ref):
    """Search tools and allow selection with arrow keys using a full-screen live view"""
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
            title=f"Search Results for '{search_term}'",
            title_style="bold purple",
            box=box.ROUNDED,
            show_header=False,
            border_style="purple",
            padding=(0, 1),
            expand=True
        )
        table.add_column("Selection", width=3)
        table.add_column("Tool Info", width=50)
        
        for idx, tool in enumerate(matches):
            if idx == selected_index:
                table.add_row(
                    ">", 
                    f"[bold green]{tool['name']}[/bold green] ([red]{tool['category']}[/red])"
                )
            else:
                table.add_row(
                    " ", 
                    f"{tool['name']} ([red]{tool['category']}[/red])"
                )
        
        panel = Panel(
            table,
            title="[bold purple]TOOL SEARCH[/bold purple]",
            subtitle="[dim]↑/↓: Navigate • Enter: Select • Esc: Cancel[/dim]",
            border_style="purple",
            padding=(1, 2)
        )
        return panel
    
    # Clear console before starting search
    console.clear()
    
    # Clear any existing keyboard events before starting
    def clear_keyboard_buffer():
        """Aggressively clear keyboard buffer"""
        try:
            import select
            import sys
            if hasattr(select, 'select'):
                # Unix-like systems
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    sys.stdin.read(1)
        except:
            pass
        
        # Also clear keyboard library buffer
        try:
            start_time = time.time()
            while time.time() - start_time < 0.1:  # Clear for 100ms
                try:
                    keyboard.read_event(timeout=0.001)
                except:
                    break
        except:
            pass
    
    # Clear buffer before starting
    clear_keyboard_buffer()
    
    tool_selected = False
    
    try:
        with Live(generate_search_display(), console=console, screen=True, auto_refresh=False) as live:
            while True:
                live.update(generate_search_display(), refresh=True)
                
                try:
                    event = keyboard.read_event()
                    if event.event_type != keyboard.KEY_DOWN:
                        continue
                    
                    if event.name == "up":
                        selected_index = max(0, selected_index - 1)
                    elif event.name == "down":
                        selected_index = min(total_matches - 1, selected_index + 1)
                    elif event.name == "enter":
                        selected_tool = matches[selected_index]
                        tool_manager.select_tool(selected_tool['index'])
                        current_page_ref[0] = (selected_tool['index'] // per_page) + 1
                        tool_selected = True
                        break
                    elif event.name == "esc":
                        break
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    console.print(f"[red]Input error: {str(e)}[/red]")
                    break
    except Exception as e:
        console.print(f"[red]Display error: {str(e)}[/red]")
        return False
    finally:
        # Aggressively clear keyboard buffer after search
        clear_keyboard_buffer()
        
        # Additional delay to ensure buffer is clear
        time.sleep(0.2)
        
        # Final buffer clear
        clear_keyboard_buffer()
    
    return tool_selected