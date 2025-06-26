
import pandas as pd
from neo4j import GraphDatabase
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Node type mapping
node_type_mapping = {
    'INTERNAL_NODE': 'InternalNode',
    'EXTERNAL_NODE': 'ExternalInterface',
    'ASSET_NODE': 'Asset',
    'Telematics ECU': 'TelematicsECU',
    'CAN-Bus': 'CANBus',
    'ECU': 'ECU',
    'NETWORK': 'Network'
}

# Function to create system model nodes and relationships
def create_sys_model_nodes_and_relationships(transaction, sys_model_data, vul_desc_data):
    id_to_name = dict(zip(sys_model_data['ID'], sys_model_data['Name']))
    
    for index, row in sys_model_data.iterrows():
        try:
            interfaces = row['Interface'].split(',') if pd.notna(row['Interface']) else []
            node_type = row['Type']
            mapped_type = node_type_mapping.get(node_type)

            if mapped_type:
                query = f"""
                    MERGE (n:{mapped_type} {{id: $id}})
                    SET n.name = $name, n.priv = $priv, n.interfaces = $interfaces, 
                        n.scr_ref = $scr_ref, n.des_ref = $des_ref, n.category = $category
                """
                transaction.run(
                    query,
                    id=row['ID'], name=row['Name'], priv=row['Priv'], interfaces=interfaces,
                    scr_ref=row['scr_ref'], des_ref=row['des_ref'], category=row['Category']
                )

                if pd.notna(row['Connects_to']):
                    connects_to_ids = [int(cid.strip()) for cid in str(row['Connects_to']).split(',')]
                    for connected_id in connects_to_ids:
                        connected_name = id_to_name.get(connected_id)
                        if connected_name:
                            transaction.run(
                                """
                                MATCH (n1 {id: $id1}), (n2 {id: $id2})
                                MERGE (n1)-[:CONNECTS_TO]->(n2)
                                """,
                                id1=row['ID'], id2=connected_id
                            )

                for interface in interfaces:
                    vul_matches = vul_desc_data[vul_desc_data['Interface'].str.contains(interface.strip(), na=False)]
                    for _, vul_row in vul_matches.iterrows():
                        transaction.run(
                            """
                            MATCH (sys_node {id: $sys_id}), (vul_node:Vulnerability {id: $vul_id})
                            MERGE (sys_node)-[:HAS_VULNERABILITY]->(vul_node)
                            """,
                            sys_id=row['ID'], vul_id=vul_row['ID']
                        )
                
                logging.info(f"Processed node: {row['Name']}")
            else:
                logging.warning(f"Unknown node type '{node_type}' for ID {row['ID']}. Skipping.")

        except Exception as e:
            logging.error(f"Error processing row {index}: {e}")

# Function to create vulnerability nodes and relationships
def create_vul_desc_nodes_and_relationships(transaction, vul_desc_data):
    for index, row in vul_desc_data.iterrows():
        try:
            interfaces = row['Interface'].split(',') if pd.notna(row['Interface']) else []

            transaction.run(
                """
                MERGE (v:Vulnerability {id: $id})
                SET v.type = $type, v.prev_step = $prev_step, v.description = $description, 
                    v.vulnerability = $vulnerability, v.cwe_number = $cwe_number, v.cvssv3 = $cvssv3, 
                    v.privilege_needed = $privilege_needed, v.privilege_acquired = $privilege_acquired, 
                    v.component = $component, v.interfaces = $interfaces, v.attack_class = $attack_class, 
                    v.target = $target
                """,
                id=row['ID'], type=row['Type'], prev_step=row['Prev_Step'], description=row['Description'], 
                vulnerability=row['Vulnerability'], cwe_number=row['CWE_number'], cvssv3=row['CVSSv3'], 
                privilege_needed=row['Privilege_needed'], privilege_acquired=row['Privilege_acquired'], 
                component=row['Component'], interfaces=interfaces, attack_class=row['Attack_Class'], 
                target=row['Target']
            )
            
            logging.info(f"Processed Vulnerability row: {index}")
        except Exception as e:
            logging.error(f"Error processing Vulnerability row {index}: {e}")

# Load data from the Excel sheets
file_path = '/Users/williamomari/Documents/python_examples/thesis_neo4j_excel/data.xlsx'  
sys_model_data = pd.read_excel(file_path, sheet_name='Sys_model', skiprows=2)
vul_desc_data = pd.read_excel(file_path, sheet_name='Vul_desc', skiprows=2)

sys_model_data.columns = ['Type', 'Category', 'ID', 'Name', 'Priv', 'Interface', 'scr_ref', 'des_ref', 'Connects_to']
vul_desc_data.columns = ['Type', 'ID', 'Prev_Step', 'Description', 'Vulnerability', 'CWE_number', 'CVSSv3', 
                         'Privilege_needed', 'Privilege_acquired', 'Component', 'Interface', 'Attack_Class', 'Target']

# Neo4j connection setup
uri = "bolt://localhost:7687"  
username = "neo4j"  
password = "KXypk$_z98@$"  

driver = GraphDatabase.driver(uri, auth=(username, password))

# Running the database operations
with driver.session() as session:
    session.execute_write(create_vul_desc_nodes_and_relationships, vul_desc_data)
    session.execute_write(create_sys_model_nodes_and_relationships, sys_model_data, vul_desc_data)

driver.close()
