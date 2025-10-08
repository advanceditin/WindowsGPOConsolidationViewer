import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET
import os
from pathlib import Path
import json
from datetime import datetime
from collections import defaultdict

class GPOViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("GPO Consolidation Viewer")
        self.root.geometry("1200x700")
        
        self.gpo_data = {}
        self.all_settings = []
        self.conflicts = []
        
        self.setup_ui()
    
    def setup_ui(self):
        # Top frame for buttons
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        ttk.Button(top_frame, text="Import GPO Backup Folder", 
                  command=self.import_gpo).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Show Conflicts", 
                  command=self.show_conflicts, 
                  style="Conflict.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Export Summary (HTML)", 
                  command=self.export_html).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Export to JSON", 
                  command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Clear All", 
                  command=self.clear_all).pack(side=tk.LEFT, padx=5)
        
        # Configure conflict button style
        style = ttk.Style()
        style.configure("Conflict.TButton", foreground="red")
        
        # Info label
        self.info_label = ttk.Label(top_frame, text="No GPOs loaded")
        self.info_label.pack(side=tk.LEFT, padx=20)
        
        # Conflict indicator
        self.conflict_label = ttk.Label(top_frame, text="", foreground="red", font=("TkDefaultFont", 9, "bold"))
        self.conflict_label.pack(side=tk.LEFT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(self.root, padding="10")
        search_frame.pack(fill=tk.X)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_settings)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Filter by GPO
        ttk.Label(search_frame, text="Filter by GPO:").pack(side=tk.LEFT, padx=(20, 5))
        self.gpo_filter = ttk.Combobox(search_frame, state="readonly", width=30)
        self.gpo_filter.pack(side=tk.LEFT)
        self.gpo_filter.bind('<<ComboboxSelected>>', lambda e: self.filter_settings())
        
        # View mode
        ttk.Label(search_frame, text="View:").pack(side=tk.LEFT, padx=(20, 5))
        self.view_mode = ttk.Combobox(search_frame, state="readonly", width=15, 
                                       values=["All Settings", "Conflicts Only"])
        self.view_mode.set("All Settings")
        self.view_mode.pack(side=tk.LEFT)
        self.view_mode.bind('<<ComboboxSelected>>', lambda e: self.filter_settings())
        
        # Main content frame with scrollbar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview for settings
        columns = ('Setting', 'Value', 'GPO Name', 'Category', 'State', 'Conflict')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='tree headings', height=20)
        
        # Column configuration
        self.tree.heading('#0', text='Path')
        self.tree.heading('Setting', text='Setting')
        self.tree.heading('Value', text='Value')
        self.tree.heading('GPO Name', text='Source GPO')
        self.tree.heading('Category', text='Category')
        self.tree.heading('State', text='State')
        self.tree.heading('Conflict', text='Conflict')
        
        self.tree.column('#0', width=200)
        self.tree.column('Setting', width=250)
        self.tree.column('Value', width=180)
        self.tree.column('GPO Name', width=150)
        self.tree.column('Category', width=120)
        self.tree.column('State', width=80)
        self.tree.column('Conflict', width=80)
        
        # Configure tags for conflict highlighting
        self.tree.tag_configure('conflict', background='#ffe6e6')
        
        # Scrollbars
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(main_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Details frame at bottom
        details_frame = ttk.LabelFrame(self.root, text="Setting Details", padding="10")
        details_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        
        self.details_text = tk.Text(details_frame, height=11, wrap=tk.WORD)
        details_scroll = ttk.Scrollbar(details_frame, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
    
    def import_gpo(self):
        folder = filedialog.askdirectory(title="Select GPO Backup Folder (Single GUID or Parent Folder)")
        if not folder:
            return
        
        self.gpo_data.clear()
        self.all_settings.clear()
        self.conflicts.clear()

        folder_path = Path(folder)
        gpo_folders = []

        # Heuristic 1: If the selected folder contains multiple GUID-named folders, process them all.
        guid_pattern = "{" + ("-" * 32) + "}" # Simplified pattern for checking if it looks like a GUID folder
        
        # Look for subdirectories that look like GPO GUIDs
        potential_gpo_dirs = [d for d in folder_path.iterdir() if d.is_dir() and len(d.name) == 38 and d.name.startswith('{') and d.name.endswith('}')]
        
        if potential_gpo_dirs:
            print(f"Detected parent folder mode. Processing {len(potential_gpo_dirs)} GPO subfolders.")
            gpo_folders.extend(potential_gpo_dirs)
        elif folder_path.name.startswith('{') and folder_path.name.endswith('}') and folder_path.is_dir():
            # Heuristic 2: If the selected folder is itself a GUID-named folder, process it directly.
            print("Detected single GPO folder mode.")
            gpo_folders.append(folder_path)
        else:
            # Fallback: Treat the selected folder as a single GPO backup (like the GPMC export dump)
             print(f"Warning: Folder name '{folder_path.name}' doesn't look like a GUID. Treating as single GPO backup.")
             gpo_folders.append(folder_path)


        total_settings_imported = 0
        
        for gpo_folder in gpo_folders:
            try:
                # Use the folder name (GUID) as the temporary GPO name. Will be replaced by gpreport info later.
                gpo_name = gpo_folder.name 
                settings = self.parse_gpo_folder(gpo_folder, gpo_name)
                
                if settings:
                    # Update GPO name if found in metadata
                    # We check for the GPO name in metadata first, and then in gpreport.xml settings list
                    gpo_display_name = next((s['value'] for s in settings if s['setting'] == 'gpoName'), gpo_name)
                    gpo_display_name = next((s['value'] for s in settings if s['setting'] == 'Name'), gpo_display_name)
                    
                    self.gpo_data[gpo_display_name] = settings
                    self.all_settings.extend(settings)
                    total_settings_imported += len(settings)
                
            except Exception as e:
                print(f"Error processing GPO folder {gpo_folder.name}: {e}")
                
        
        if total_settings_imported > 0:
            self.detect_conflicts()
            self.update_display()
            messagebox.showinfo("Success", f"Successfully imported settings from {len(self.gpo_data)} GPO(s). Total settings: {total_settings_imported}")
        else:
            messagebox.showwarning("Warning", "No settings found in the selected folder(s). Please ensure the backup structure is correct.")


    def parse_gpo_folder(self, folder, gpo_name):
        settings = []
        folder_path = Path(folder)
        
        print(f"\n--- Searching GPO folder: {folder_path} ---")
        
        # --- 1. Find the core files using recursive globbing ---
        
        # Find gpreport.xml (most important, should be in the root or close to it)
        gpreport_xml_candidates = list(folder_path.rglob("gpreport.xml"))
        gpreport_xml = gpreport_xml_candidates[0] if gpreport_xml_candidates else None
        print(f"gpreport.xml found: {gpreport_xml is not None}")
        
        # Find GPT.INI
        gpt_ini_candidates = list(folder_path.rglob("GPT.INI"))
        gpt_ini = gpt_ini_candidates[0] if gpt_ini_candidates else None
        print(f"GPT.INI found: {gpt_ini is not None} (Skipping if not present per user request)")

        # Find Registry.pol (often deeply nested in DomainSysvol)
        registry_pol_candidates = list(folder_path.rglob("Registry.pol"))
        # We look for any instance, as the path might be different if the user selected a high-level folder
        registry_pol = registry_pol_candidates[0] if registry_pol_candidates else None
        print(f"Registry.pol found: {registry_pol is not None} (Skipping if not present per user request)")
        
        # --- 2. Parse the found files ---

        # Parse gpreport.xml if exists
        if gpreport_xml and gpreport_xml.exists():
            settings.extend(self.parse_gpreport_xml(gpreport_xml, gpo_name))
        
        # Parse GPT.INI (Only if found, as requested by the user)
        if gpt_ini and gpt_ini.exists():
            settings.extend(self.parse_gpt_ini(gpt_ini, gpo_name))

        # Parse Registry.pol (Only if found, as requested by the user)
        if registry_pol and registry_pol.exists():
            settings.extend(self.parse_registry_pol(registry_pol, gpo_name))
        
        
        # --- 3. EXPLICITLY FIND AND PARSE GPP XML FILES (Group Policy Preferences) ---
        
        # Define common GPP paths/file names relative to the GPO folder
        GPP_XML_PATTERNS = [
            'User/Preferences/Drives/*.xml',           # Drive Maps
            'User/Preferences/Files/*.xml',            # Files
            'User/Preferences/Shortcuts/*.xml',        # Shortcuts
            'User/Preferences/Printers/*.xml',         # Printers
            'Machine/Preferences/ScheduledTasks/*.xml', # Scheduled Tasks
            'Machine/Preferences/LocalUsersAndGroups/*.xml', # LUSG
        ]
        
        gpp_settings_found = 0
        
        for pattern in GPP_XML_PATTERNS:
            for gpp_path in folder_path.rglob(pattern):
                if gpp_path.exists():
                    settings.extend(self.parse_generic_xml(gpp_path, gpo_name, folder_path))
                    gpp_settings_found += 1
        
        print(f"GPP XML files processed (based on pattern match): {gpp_settings_found}")

        # Look for other top-level XML files (e.g., backup/bkupinfo)
        for xml_path in folder_path.rglob("*.xml"):
            xml_name_lower = xml_path.name.lower()
            if xml_name_lower == "backup.xml" or xml_name_lower == "bkupinfo.xml":
                settings.extend(self.parse_metadata_xml(xml_path, gpo_name, folder_path))
        
        print(f"--- Finished parsing GPO: {gpo_name}. Total settings found: {len(settings)} ---")
        return settings
    
    def parse_metadata_xml(self, file_path, gpo_name, base_path):
        """Parses simple backup metadata files like backup.xml and bkupInfo.xml"""
        settings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            rel_path = os.path.relpath(file_path, base_path)
            category = file_path.stem.capitalize()

            # Extract basic metadata
            for child in root:
                # Use split to handle namespaces if present, focusing only on the tag name
                tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                value = child.text.strip() if child.text and child.text.strip() else ""
                
                if tag in ['gpoName', 'domainName', 'gpoId', 'backupTime', 'Name'] and value:
                    settings.append({
                        'gpo': gpo_name,
                        'category': category,
                        'path': rel_path,
                        'setting': tag,
                        'value': value,
                        'state': 'Set',
                        'details': f"Metadata from {file_path.name}: {tag}={value}",
                        'setting_key': f'{category}|{tag}'
                    })
        except Exception as e:
            print(f"Error parsing metadata file {file_path.name}: {e}")
            pass
        return settings

    def parse_registry_pol(self, file_path, gpo_name):
        settings = []
        # Since the user stated this file might not be present, we only log its presence.
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                settings.append({
                    'gpo': gpo_name,
                    'category': 'Registry (Binary POL)',
                    # Path is relative to the selected GPO folder
                    'path': os.path.relpath(file_path, Path(file_path).parent.parent.parent.parent), 
                    'setting': 'Registry Policy File (Presence)',
                    'value': f'Binary file ({len(data)} bytes)',
                    'state': 'Present',
                    'details': f'Registry policy file found at {file_path}. Content requires binary parsing.',
                    'setting_key': 'Registry (Binary POL)|Registry Policy File'
                })
        except Exception as e:
            print(f"Error reading Registry.pol for {gpo_name}: {e}")
            pass
        return settings
    
    def parse_gpreport_xml(self, file_path, gpo_name):
        """
        Parses the gpreport.xml file to extract detailed settings from various
        Client-Side Extensions (CSEs).
        """
        settings = []
        
        # Define common XML namespace URIs for gpreport.xml
        GPO_NS = 'http://www.microsoft.com/GroupPolicy/Settings'
        GPT_NS = 'http://www.microsoft.com/GroupPolicy/Types'
        SEC_NS = 'http://www.microsoft.com/GroupPolicy/Settings/Security'
        
        # We define a default map for ElementTree to resolve prefixes
        NAMESPACES = {
            'gp': GPO_NS,
            'gpt': GPT_NS,
            'sec': SEC_NS,
        }
        
        try:
            # Register namespaces for cleaner XPath
            for prefix, uri in NAMESPACES.items():
                ET.register_namespace(prefix, uri)
                
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # --- 1. Find the GPO element(s) ---
            gpo_elements = []
            for elem in root.iter(f'{{{GPO_NS}}}GPO'):
                gpo_elements.append(elem)

            if not gpo_elements:
                print("Error: <GPO> element not found using standard namespace.")
                return settings
                
            for gpo_element in gpo_elements:
                
                # --- A. Extract GPO Name (from root level) ---
                gpo_name_elem = gpo_element.find(f'{{{GPO_NS}}}Name')
                current_gpo_name = gpo_name_elem.text if gpo_name_elem is not None else gpo_name 

                # Look for settings within <Computer> and <User> sections
                computer_block = gpo_element.find(f'{{{GPO_NS}}}Computer')
                user_block = gpo_element.find(f'{{{GPO_NS}}}User')

                blocks_to_process = []
                if computer_block is not None:
                    blocks_to_process.append(('Computer', computer_block))
                if user_block is not None:
                    blocks_to_process.append(('User', user_block))
                
                for block_type, block in blocks_to_process:
                    # Find the ExtensionData block within the Computer/User block
                    ext_data_block = block.find(f'{{{GPO_NS}}}ExtensionData')
                    if ext_data_block is None:
                        continue
                    
                    # Iterate through all direct children of ExtensionData
                    for ext_container in ext_data_block:
                        
                        # The Category name is often stored in the next sibling <Name> tag, or in an attribute
                        
                        # Heuristic: The category name is often in a *sibling* <Name> tag
                        category_name_elem = ext_data_block.find(f'{{{GPO_NS}}}Name')
                        category = category_name_elem.text if category_name_elem is not None else 'Unknown'

                        # Second Heuristic: Try to infer category from the XML content tag itself
                        if ext_container.tag.endswith('SecuritySettings'):
                            category = 'Security'
                        elif ext_container.tag.endswith('RegistrySettings'):
                             category = 'Registry'
                        
                        print(f"--- Processing Category: {category} in GPO: {current_gpo_name} (Block: {block_type}) ---")
                        
                        # --- C. Handle Security Settings (Account Policy, User Rights, etc.) ---
                        if category == 'Security':
                            # Look for the SecuritySettings container, which is often prefixed
                            security_settings_block = ext_container.find(f'.//{{{SEC_NS}}}SecuritySettings') or ext_container

                            # 1. Account Policies (Account)
                            for account_policy in security_settings_block.iter(f'{{{SEC_NS}}}Account'): 
                                try:
                                    name_elem = account_policy.find(f'{{{SEC_NS}}}Name')
                                    type_elem = account_policy.find(f'{{{SEC_NS}}}Type')
                                    
                                    setting_name = name_elem.text.strip() if name_elem is not None and name_elem.text else 'Unknown Account Policy'
                                    setting_type = type_elem.text.strip() if type_elem is not None and type_elem.text else 'Policy'

                                    value_elem_num = account_policy.find(f'{{{SEC_NS}}}SettingNumber')
                                    value_elem_bool = account_policy.find(f'{{{SEC_NS}}}SettingBoolean')
                                    
                                    final_value_elem = value_elem_num if value_elem_num is not None else value_elem_bool

                                    setting_value = final_value_elem.text.strip() if final_value_elem is not None and final_value_elem.text else 'N/A'
                                    
                                    settings.append({
                                        'gpo': current_gpo_name,
                                        'category': f'Account Policies - {setting_type}',
                                        'path': current_gpo_name,
                                        'setting': setting_name,
                                        'value': setting_value,
                                        'state': 'Configured',
                                        'details': ET.tostring(account_policy, encoding='unicode', method='xml').strip(),
                                        'setting_key': f'Security|Account|{setting_name}'
                                    })
                                except Exception as e:
                                    print(f"Error parsing Account Policy setting: {e}")
                            
                            # 2. Security Options (SecurityOptions)
                            for sec_option in security_settings_block.iter(f'{{{SEC_NS}}}SecurityOptions'):
                                try:
                                    key_name_elem = sec_option.find(f'{{{SEC_NS}}}KeyName')
                                    display_name_elem = sec_option.find(f'{{{SEC_NS}}}Display/{{{SEC_NS}}}Name')
                                    value_elem_str = sec_option.find(f'{{{SEC_NS}}}Display/{{{SEC_NS}}}DisplayString')
                                    value_elem_num = sec_option.find(f'{{{SEC_NS}}}SettingNumber')
                                    
                                    setting_name = display_name_elem.text.strip() if display_name_elem is not None and display_name_elem.text else (key_name_elem.text.strip() if key_name_elem is not None and key_name_elem.text else 'Unknown Security Option')
                                    
                                    final_value = (value_elem_str.text.strip() if value_elem_str is not None else 
                                                value_elem_num.text.strip() if value_elem_num is not None else 
                                                'Configured')
                                    
                                    settings.append({
                                        'gpo': current_gpo_name,
                                        'category': 'Security Settings - Options',
                                        'path': key_name_elem.text.strip() if key_name_elem is not None else current_gpo_name,
                                        'setting': setting_name,
                                        'value': final_value,
                                        'state': 'Configured',
                                        'details': ET.tostring(sec_option, encoding='unicode', method='xml').strip(),
                                        'setting_key': f'Security|Option|{setting_name}'
                                    })
                                except Exception as e:
                                    print(f"Error parsing Security Option setting: {e}")

                            # 3. Audit Policies (Audit) - Still using iter() for flexibility
                            for audit in security_settings_block.iter('Audit'): 
                                try:
                                    name_elem = audit.find('Name') or audit.find(f'{{{SEC_NS}}}Name')
                                    success_elem = audit.find('SuccessAttempts') or audit.find(f'{{{SEC_NS}}}SuccessAttempts')
                                    failure_elem = audit.find('FailureAttempts') or audit.find(f'{{{SEC_NS}}}FailureAttempts')
                                    
                                    setting_name = name_elem.text.strip() if name_elem is not None and name_elem.text else 'Unknown Audit Policy'
                                    success = success_elem.text.strip().lower() == 'true' if success_elem is not None and success_elem.text else 'N/A'
                                    failure = failure_elem.text.strip().lower() == 'true' if failure_elem is not None and failure_elem.text else 'N/A'
                                    
                                    settings.append({
                                        'gpo': current_gpo_name,
                                        'category': 'Security Settings - Audit Policy',
                                        'path': current_gpo_name,
                                        'setting': setting_name,
                                        'value': f"Success: {success}, Failure: {failure}",
                                        'state': 'Configured',
                                        'details': ET.tostring(audit, encoding='unicode', method='xml').strip(),
                                        'setting_key': f'Security|Audit|{setting_name}'
                                    })
                                except Exception as e:
                                    print(f"Error parsing Audit setting: {e}")
                            
                            # 4. User Rights Assignments (UserRightsAssignment) - Still using iter() for flexibility
                            for user_rights in security_settings_block.iter('UserRightsAssignment'):
                                try:
                                    name_elem = user_rights.find('Name') or user_rights.find(f'{{{SEC_NS}}}Name')
                                    
                                    setting_name = name_elem.text.strip() if name_elem is not None and name_elem.text else 'Unknown User Right'
                                    members = []
                                    
                                    for member in user_rights.iter('Member'):
                                        member_name_elem = member.find('Name') or member.find(f'{{{GPT_NS}}}Name')
                                        if member_name_elem is not None and member_name_elem.text:
                                            members.append(member_name_elem.text.strip())
                                            
                                    settings.append({
                                        'gpo': current_gpo_name,
                                        'category': 'Security Settings - User Rights',
                                        'path': current_gpo_name,
                                        'setting': setting_name,
                                        'value': ", ".join(members) if members else "(Not Defined)",
                                        'state': 'Configured',
                                        'details': ET.tostring(user_rights, encoding='unicode', method='xml').strip(),
                                        'setting_key': f'Security|UserRight|{setting_name}'
                                    })
                                except Exception as e:
                                    print(f"Error parsing User Rights setting: {e}")

                        # --- D. Handle Administrative Templates / Registry Settings (Policy tags) ---
                        elif category == 'Registry':
                            # For Registry/Admin Templates, find policy blocks
                            for policy in ext_container.findall(f'.//{{{GPO_NS}}}Policy'):
                                try:
                                    name = policy.find(f'{{{GPO_NS}}}Name')
                                    state = policy.find(f'{{{GPO_NS}}}State')
                                    key = policy.find(f'{{{GPO_NS}}}Key')
                                    value_elem = policy.find(f'{{{GPO_NS}}}Value')
                                    
                                    setting_name = name.text.strip() if name is not None and name.text else 'Unknown Registry Policy'
                                    setting_state = state.text.strip() if state is not None and state.text else 'N/A'
                                    setting_path = key.text.strip() if key is not None and key.text else 'N/A'
                                    value = value_elem.text.strip() if value_elem is not None and value_elem.text else ""
                                    
                                    settings.append({
                                        'gpo': current_gpo_name,
                                        'category': 'Admin Templates',
                                        'path': setting_path,
                                        'setting': setting_name,
                                        'value': value,
                                        'state': setting_state,
                                        'details': ET.tostring(policy, encoding='unicode', method='xml').strip(), 
                                        'setting_key': f'RegTemplate|{setting_path}|{setting_name}'
                                    })
                                except Exception as e:
                                    print(f"Error parsing Admin Template setting: {e}")

                        # --- E. Generic Parsing for other GPO Settings (PolicyList/Policy) ---
                        else:
                            # Fallback for other extensions (e.g., Applocker, etc.)
                            for setting_item in ext_container.findall(f'.//{{{GPO_NS}}}Policy') + ext_container.findall(f'.//{{{GPO_NS}}}PolicyList/*'):
                                try:
                                    tag = setting_item.tag.split('}')[-1] if '}' in setting_item.tag else setting_item.tag
                                    
                                    setting_name = tag
                                    setting_value = ''
                                    setting_path = category
                                    setting_state = 'Configured'
                                    
                                    name_elem = setting_item.find(f'{{{GPO_NS}}}Name') or \
                                                setting_item.find(f'{{{GPO_NS}}}Action')
                                    
                                    if name_elem is not None and name_elem.text:
                                        setting_name = f"{tag}: {name_elem.text.strip()}"

                                    value_elem = setting_item.find(f'{{{GPO_NS}}}Value') or \
                                                 setting_item.find(f'{{{GPO_NS}}}Type')
                                                
                                    if value_elem is not None and value_elem.text:
                                        setting_value = value_elem.text.strip()
                                    
                                    if setting_name != tag or setting_value:
                                        settings.append({
                                            'gpo': current_gpo_name,
                                            'category': category,
                                            'path': setting_path,
                                            'setting': setting_name,
                                            'value': setting_value,
                                            'state': setting_state,
                                            'details': ET.tostring(setting_item, encoding='unicode', method='xml').strip(), 
                                            'setting_key': f'{category}|{setting_name}|{setting_value}'
                                        })
                                except Exception as e:
                                    print(f"Error parsing Generic setting: {e}")

        except ET.ParseError as pe:
            print(f"XML Parse Error in gpreport.xml for {gpo_name}: {pe}")
        except Exception as e:
            print(f"General Error parsing gpreport.xml for {gpo_name}: {e}")
            pass 
        return settings
    
    def parse_gpt_ini(self, file_path, gpo_name):
        settings = []
        try:
            # Try reading with common encodings if default fails
            encodings = ['utf-16', 'utf-8', 'latin-1']
            file_content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        file_content = f.read()
                        break
                except UnicodeDecodeError:
                    continue
                except FileNotFoundError:
                    return settings
            
            if file_content is None:
                raise UnicodeDecodeError("Could not read file with common encodings.")

            for line in file_content.splitlines():
                line = line.strip()
                if '=' in line and not line.startswith('['):
                    key, value = line.split('=', 1)
                    settings.append({
                        'gpo': gpo_name,
                        'category': 'GPT Configuration',
                        'path': 'GPT.INI',
                        'setting': key.strip(),
                        'value': value.strip(),
                        'state': 'Set',
                        'details': f'GPT.INI setting: {key} = {value}',
                        'setting_key': f'GPT Configuration|{key.strip()}'
                    })
        except Exception as e:
            print(f"Error reading GPT.INI for {gpo_name}: {e}")
            pass
        return settings
    
    def parse_generic_xml(self, file_path, gpo_name, base_path):
        settings = []
        
        # Define specific namespaces for GPP files for better tag resolution
        GPP_NAMESPACES = {
            'c': 'http://www.microsoft.com/GroupPolicy/Settings/Common',
            'ad': 'http://www.microsoft.com/GroupPolicy/Settings/AdmTmpl',
            'fs': 'http://www.microsoft.com/GroupPolicy/Settings/Files',
            'drv': 'http://www.microsoft.com/GroupPolicy/Settings/Drives',
            'sch': 'http://www.microsoft.com/GroupPolicy/Settings/ScheduledTasks',
            'lusg': 'http://www.microsoft.com/GroupPolicy/Settings/LocalUsersAndGroups'
        }
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # The relative path helps in unique identification
            rel_path = os.path.relpath(file_path, base_path) 
            # Derive category from folder name if possible, otherwise use a default
            path_parts = list(file_path.parts)
            category = 'GPP - Other'
            for part in path_parts:
                if part == 'Drives': category = "GPP - Drive Maps"
                elif part == 'Files': category = "GPP - Files"
                elif part == 'LocalUsersAndGroups': category = "GPP - LUSG"
                elif part == 'ScheduledTasks': category = "GPP - Scheduled Tasks"

            # Check for GPP root elements like <Drives>, <Files>, etc.
            if root.tag.endswith('Drives'): category = "GPP - Drive Maps"
            elif root.tag.endswith('Files'): category = "GPP - Files"
            elif root.tag.endswith('LocalUsersAndGroups'): category = "GPP - LUSG"
            elif root.tag.endswith('ScheduledTasks'): category = "GPP - Scheduled Tasks"
            
            # Try to find items under the main collections tag (e.g., <Drive> tags under <Drives>)
            for item in root.findall('./*/*'):
                tag = item.tag.split('}')[-1] if '}' in item.tag else item.tag
                
                # Try to get action from common namespace
                action_type = item.get(f"{{{GPP_NAMESPACES['c']}}}action")
                
                # Find the primary name or description
                name = item.get('name') or item.get('computerName') or item.get('newName')
                if not name and item.find(f"./{{{GPP_NAMESPACES['c']}}}Name") is not None:
                     name = item.find(f"./{{{GPP_NAMESPACES['c']}}}Name").text
                
                if name or action_type:
                    setting_name = f"[{action_type or tag}] {name or tag}"
                    
                    # Extract target value/path if available (heuristic)
                    value = item.get('path') or item.get('to') or item.get('run') or item.get('user') or 'Configured'
                    value = value.strip()[:100] if value else 'Configured'

                    settings.append({
                        'gpo': gpo_name,
                        'category': category,
                        'path': rel_path,
                        'setting': setting_name,
                        'value': value, 
                        'state': action_type or 'Configured',
                        'details': ET.tostring(item, encoding='unicode', method='xml').strip(), 
                        'setting_key': f'{category}|{setting_name}'
                    })

        except Exception as e:
            print(f"Error parsing generic XML file {file_path.name} for {gpo_name}: {e}")
            pass
        return settings
    
    def detect_conflicts(self):
        """Detect conflicting settings between GPOs"""
        self.conflicts = []
        
        # Group settings by their setting_key
        setting_groups = defaultdict(list)
        for setting in self.all_settings:
            # Ensure all settings have 'is_conflict' key initialized to False
            setting['is_conflict'] = False
            
            key = setting.get('setting_key', f"{setting['category']}|{setting['setting']}")
            setting_groups[key].append(setting)
        
        # Find conflicts (same setting, different values, different GPOs)
        for key, settings in setting_groups.items():
            if len(settings) > 1:
                # Check if there are different values
                values = set()
                gpos = set()
                for s in settings:
                    values.add(s['value'])
                    gpos.add(s['gpo'])
                
                # Conflict if multiple GPOs define same setting with different values
                if len(gpos) > 1 and len(values) > 1:
                    conflict_info = {
                        'setting_key': key,
                        'setting_name': settings[0]['setting'],
                        'category': settings[0]['category'],
                        'instances': settings
                    }
                    self.conflicts.append(conflict_info)
                    
                    # Mark all instances as conflicting
                    for s in settings:
                        s['is_conflict'] = True
    
    def show_conflicts(self):
        """Show a detailed conflict analysis window"""
        if not self.conflicts:
            messagebox.showinfo("No Conflicts", "No conflicting settings found between GPOs.")
            return
        
        conflict_window = tk.Toplevel(self.root)
        conflict_window.title("Conflict Analysis")
        conflict_window.geometry("900x600")
        
        # Header
        header = ttk.Label(conflict_window, 
                          text=f"Found {len(self.conflicts)} conflicting settings",
                          font=("TkDefaultFont", 12, "bold"))
        header.pack(pady=10)
        
        # Create treeview for conflicts
        frame = ttk.Frame(conflict_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('Setting', 'Category', 'Instances')
        conflict_tree = ttk.Treeview(frame, columns=columns, show='tree headings')
        
        conflict_tree.heading('#0', text='Conflict Details')
        conflict_tree.heading('Setting', text='Setting Name')
        conflict_tree.heading('Category', text='Category')
        conflict_tree.heading('Instances', text='# of Conflicts')
        
        conflict_tree.column('#0', width=300)
        conflict_tree.column('Setting', width=250)
        conflict_tree.column('Category', width=150)
        conflict_tree.column('Instances', width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=conflict_tree.yview)
        conflict_tree.configure(yscrollcommand=scrollbar.set)
        
        conflict_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate conflict tree
        for conflict in self.conflicts:
            parent = conflict_tree.insert('', 'end',
                                         text=f"⚠ {conflict['setting_name']}",
                                         values=(conflict['setting_name'], 
                                               conflict['category'],
                                               len(conflict['instances'])))
            
            for instance in conflict['instances']:
                conflict_tree.insert(parent, 'end',
                                   text=f"  GPO: {instance['gpo']}",
                                   values=(f"Value: {instance['value']}", 
                                          instance['state'], ''))
        
        # Export button
        ttk.Button(conflict_window, text="Export Conflicts to HTML",
                  command=lambda: self.export_conflicts_html()).pack(pady=10)
    
    def update_display(self):
        self.tree.delete(*self.tree.get_children())
        
        # Update info label
        total_settings = len(self.all_settings)
        total_gpos = len(self.gpo_data)
        self.info_label.config(text=f"Loaded {total_gpos} GPOs with {total_settings} total settings")
        
        # Update conflict indicator
        if self.conflicts:
            self.conflict_label.config(text=f"⚠ {len(self.conflicts)} conflicts detected!")
        else:
            self.conflict_label.config(text="")
        
        # Update GPO filter dropdown
        gpo_names = ['All GPOs'] + list(self.gpo_data.keys())
        self.gpo_filter['values'] = gpo_names
        self.gpo_filter.set('All GPOs')
        
        self.filter_settings()
    
    def filter_settings(self, *args):
        self.tree.delete(*self.tree.get_children())
        
        search_term = self.search_var.get().lower()
        gpo_filter = self.gpo_filter.get()
        view_mode = self.view_mode.get()
        
        # Group settings first by GPO, then by Category (New Logic)
        gpos_to_display = defaultdict(lambda: defaultdict(list))
        
        for setting in self.all_settings:
            # Apply view mode filter
            if view_mode == "Conflicts Only" and not setting.get('is_conflict', False):
                continue
            
            # Apply GPO filter
            if gpo_filter and gpo_filter != 'All GPOs' and setting['gpo'] != gpo_filter:
                continue
            
            # Apply search filter
            if search_term:
                searchable = f"{setting['setting']} {setting['value']} {setting['gpo']} {setting['category']}".lower()
                if search_term not in searchable:
                    continue
            
            # Grouping: GPO Name -> Category -> List of settings
            gpo_name = setting['gpo']
            category = setting.get('category', 'Other')
            gpos_to_display[gpo_name][category].append(setting)
        
        # Insert into tree: GPO Name is the top level
        for gpo_name, categories in sorted(gpos_to_display.items()):
            # Insert the GPO Name as the main parent node
            gpo_id = self.tree.insert('', 'end', text=f"GPO: {gpo_name}", open=True, tags=('gpo_header',))
            
            # Then insert categories as children
            for category, settings in sorted(categories.items()):
                cat_id = self.tree.insert(gpo_id, 'end', text=category, open=True, tags=('category_header',))
                
                # Finally, insert individual settings
                for setting in settings:
                    is_conflict = setting.get('is_conflict', False)
                    conflict_marker = "⚠ YES" if is_conflict else "No"
                    
                    tags = [setting['gpo']]
                    if is_conflict:
                        tags.append('conflict')
                    
                    self.tree.insert(cat_id, 'end', 
                                   text=setting['path'],
                                   values=(
                                       setting['setting'],
                                       setting['value'],
                                       setting['gpo'],
                                       setting['category'],
                                       setting['state'],
                                       conflict_marker
                                   ),
                                   tags=tuple(tags))
    
    def on_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item['values']
            
            # Only proceed if values are present (i.e., not a GPO or Category header)
            if values:
                self.details_text.delete(1.0, tk.END)
                
                # Extract identifiers from the selected row's values
                selected_setting_name = values[0]
                selected_gpo_name = values[2]
                
                # Find the full setting details in self.all_settings
                for setting in self.all_settings:
                    setting_key = setting.get('setting_key')
                    
                    # Heuristic to match the setting in the treeview to the one in self.all_settings
                    match_setting = setting['setting'] == selected_setting_name or setting['setting'] == selected_setting_name.replace("⚠ ", "")
                    
                    if match_setting and setting['gpo'] == selected_gpo_name:
                        
                        details = f"GPO: {setting['gpo']}\n"
                        details += f"Category: {setting['category']}\n"
                        details += f"Path: {setting['path']}\n"
                        details += f"Setting: {setting['setting']}\n"
                        details += f"Value: {setting['value']}\n"
                        details += f"State: {setting['state']}\n"
                        details += f"Unique Key: {setting_key}\n"
                        
                        if setting.get('is_conflict', False):
                            details += f"\n⚠ CONFLICT DETECTED!\n"
                            details += "This setting conflicts with:\n"
                            
                            # Find other instances of this setting using the unique key
                            for other in self.all_settings:
                                if (other.get('setting_key') == setting_key and 
                                    other['gpo'] != setting['gpo']):
                                    details += f"  - GPO '{other['gpo']}': {other['value']}\n"
                        
                        details += f"\nFull Details (XML/Text):\n{setting.get('details', 'N/A')}"
                        
                        self.details_text.insert(1.0, details)
                        break
    
    def clear_all(self):
        if messagebox.askyesno("Confirm", "Clear all loaded GPOs?"):
            self.gpo_data.clear()
            self.all_settings.clear()
            self.conflicts.clear()
            self.tree.delete(*self.tree.get_children())
            self.details_text.delete(1.0, tk.END)
            self.info_label.config(text="No GPOs loaded")
            self.conflict_label.config(text="")
            self.gpo_filter['values'] = []
    
    def export_json(self):
        if not self.all_settings:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                export_data = {
                    'export_date': datetime.now().isoformat(),
                    'total_gpos': len(self.gpo_data),
                    'total_settings': len(self.all_settings),
                    'conflicts': len(self.conflicts),
                    'gpos': list(self.gpo_data.keys()),
                    'settings': self.all_settings,
                    'conflict_details': self.conflicts
                }
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Success", f"Exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_html(self):
        """Export a comprehensive HTML summary"""
        if not self.all_settings:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            html = self.generate_html_summary()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Success", f"HTML summary exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_conflicts_html(self):
        """Export only conflicts to HTML"""
        if not self.conflicts:
            messagebox.showwarning("Warning", "No conflicts to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            html = self.generate_conflicts_html()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Success", f"Conflict report exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def generate_html_summary(self):
        """Generate a comprehensive HTML summary of all GPO settings"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPO Settings Summary</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 10px 20px;
            background: #f0f0f0;
            border-radius: 5px;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }}
        .gpo-section {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .gpo-title {{
            font-size: 20px;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .category {{
            margin: 15px 0;
        }}
        .category-title {{
            font-weight: bold;
            color: #555;
            margin: 10px 0 5px 0;
            font-size: 16px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th {{
            background-color: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .conflict {{
            background-color: #ffe6e6 !important;
        }}
        .conflict-badge {{
            background-color: #dc3545;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }}
        .toc {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .toc a {{
            color: #667eea;
            text-decoration: none;
            display: block;
            padding: 5px 0;
        }}
        .toc a:hover {{
            text-decoration: underline;
        }}
        .value-cell {{
            max-width: 300px;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GPO Settings Consolidation Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="stat">
            <div class="stat-value">{len(self.gpo_data)}</div>
            <div class="stat-label">Total GPOs</div>
        </div>
        <div class="stat">
            <div class="stat-value">{len(self.all_settings)}</div>
            <div class="stat-label">Total Settings</div>
        </div>
        <div class="stat">
            <div class="stat-value">{len(self.conflicts)}</div>
            <div class="stat-label">Conflicts</div>
        </div>
    </div>
    
    <div class="toc">
        <h3>Table of Contents</h3>
        <ul>
"""
        
        # Add TOC entries for each GPO
        for gpo_name in sorted(self.gpo_data.keys()):
            gpo_id = gpo_name.replace(' ', '_').replace('/', '_')
            html += f'            <li><a href="#{gpo_id}">{gpo_name}</a></li>\n'
        
        if self.conflicts:
            html += '            <li><a href="#conflicts">⚠ Conflict Analysis</a></li>\n'
        
        html += """        </ul>
    </div>
"""
        
        # Add conflict section if there are conflicts
        if self.conflicts:
            html += """
    <div class="gpo-section" id="conflicts">
        <div class="gpo-title">⚠ Conflict Analysis</div>
        <p>The following settings have conflicting values across different GPOs:</p>
        <table>
            <tr>
                <th>Setting Name</th>
                <th>Category</th>
                <th>Conflicting GPOs</th>
                <th>Values</th>
            </tr>
"""
            for conflict in self.conflicts:
                gpo_list = '<br>'.join([f"• {inst['gpo']}" for inst in conflict['instances']])
                value_list = '<br>'.join([f"• {inst['gpo']}: <strong>{inst['value']}</strong>" 
                                         for inst in conflict['instances']])
                
                html += f"""            <tr class="conflict">
                <td>{conflict['setting_name']}</td>
                <td>{conflict['category']}</td>
                <td>{gpo_list}</td>
                <td class="value-cell">{value_list}</td>
            </tr>
"""
            html += """        </table>
    </div>
"""
        
        # Add settings grouped by GPO
        for gpo_name in sorted(self.gpo_data.keys()):
            gpo_id = gpo_name.replace(' ', '_').replace('/', '_')
            settings = self.gpo_data[gpo_name]
            
            html += f"""
    <div class="gpo-section" id="{gpo_id}">
        <div class="gpo-title">{gpo_name}</div>
        <p>Total settings: {len(settings)}</p>
"""
            
            # Group by category
            categories = defaultdict(list)
            for setting in settings:
                categories[setting['category']].append(setting)
            
            for category, cat_settings in sorted(categories.items()):
                html += f"""
        <div class="category">
            <div class="category-title">{category} ({len(cat_settings)} settings)</div>
            <table>
                <tr>
                    <th>Setting</th>
                    <th>Value</th>
                    <th>State</th>
                    <th>Path</th>
                </tr>
"""
                for setting in cat_settings:
                    conflict_class = 'conflict' if setting.get('is_conflict') else ''
                    conflict_badge = '<span class="conflict-badge">CONFLICT</span>' if setting.get('is_conflict') else ''
                    
                    html += f"""                <tr class="{conflict_class}">
                    <td>{setting['setting']} {conflict_badge}</td>
                    <td class="value-cell">{setting['value']}</td>
                    <td>{setting['state']}</td>
                    <td>{setting['path']}</td>
                </tr>
"""
                html += """            </table>
        </div>
"""
            html += """    </div>
"""
        
        html += """
</body>
</html>"""
        
        return html
    
    def generate_conflicts_html(self):
        """Generate HTML report focused on conflicts"""
        if not self.conflicts:
            messagebox.showwarning("Warning", "No conflicts to export")
            return
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPO Conflict Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .conflict-item {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 5px solid #dc3545;
        }}
        .conflict-title {{
            font-size: 18px;
            font-weight: bold;
            color: #dc3545;
            margin-bottom: 10px;
        }}
        .conflict-details {{
            margin: 10px 0;
        }}
        .gpo-instance {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }}
        .gpo-name {{
            font-weight: bold;
            color: #333;
        }}
        .setting-value {{
            color: #667eea;
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            word-wrap: break-word; /* Ensure long values wrap */
        }}
        .category-badge {{
            background: #6c757d;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 12px;
            display: inline-block;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚠ GPO Conflict Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Conflicts: {len(self.conflicts)}</p>
    </div>
"""
        
        for i, conflict in enumerate(self.conflicts, 1):
            html += f"""
    <div class="conflict-item">
        <div class="conflict-title">Conflict #{i}: {conflict['setting_name']}</div>
        <span class="category-badge">{conflict['category']}</span>
        <div class="conflict-details">
            <p><strong>This setting is defined differently in {len(conflict['instances'])} GPOs:</strong></p>
"""
            
            for instance in conflict['instances']:
                html += f"""
            <div class="gpo-instance">
                <div class="gpo-name">GPO: {instance['gpo']}</div>
                <div>Value: <span class="setting-value">{instance['value']}</span></div>
                <div>State: {instance['state']}</div>
                <div>Path: {instance['path']}</div>
            </div>
"""
            
            html += """        </div>
    </div>
"""
        
        html += """
</body>
</html>"""
        
        return html

if __name__ == "__main__":
    root = tk.Tk()
    app = GPOViewer(root)
    root.mainloop()
