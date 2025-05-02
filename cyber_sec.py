import os
from neo4j import GraphDatabase
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
import pandas as pd
from typing import List, Dict, Any
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
import json
import re

# Configuration
NEO4J_URI = os.environ.get("NEO4J_URI", "your-api-key-here")
NEO4J_USER = os.environ.get("NEO4J_USER", "your-api-key-here")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "your-api-key-here")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "your-api-key-here")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "your-api-key-here")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "your-api-key-here")

# Connect to Neo4j
class Neo4jDatabase:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
        
    def create_asset(self, name, ip_address, asset_type):
        with self.driver.session() as session:
            session.run(
                "CREATE (a:Asset {name: $name, ip: $ip, type: $type})",
                name=name, ip=ip_address, type=asset_type
            )
    
    def create_port(self, asset_name, port_number, service, is_open=True):
        with self.driver.session() as session:
            session.run(
                """
                MATCH (a:Asset {name: $asset_name})
                CREATE (p:Port {number: $port_number, service: $service, is_open: $is_open})
                CREATE (a)-[:HAS_PORT]->(p)
                """,
                asset_name=asset_name, port_number=port_number, 
                service=service, is_open=is_open
            )
    
    def create_vulnerability(self, name, description, cvss_score, affected_service):
        with self.driver.session() as session:
            session.run(
                """
                CREATE (v:Vulnerability {
                    name: $name, 
                    description: $description, 
                    cvss: $cvss,
                    affected_service: $affected_service
                })
                """,
                name=name, description=description, 
                cvss=cvss_score, affected_service=affected_service
            )
    
    def link_vulnerability_to_port(self, vuln_name, asset_name, port_number):
        with self.driver.session() as session:
            session.run(
                """
                MATCH (v:Vulnerability {name: $vuln_name})
                MATCH (a:Asset {name: $asset_name})-[:HAS_PORT]->(p:Port {number: $port_number})
                CREATE (p)-[:HAS_VULNERABILITY]->(v)
                """,
                vuln_name=vuln_name, asset_name=asset_name, port_number=port_number
            )
    
    def run_query(self, query, params=None):
        if params is None:
            params = {}
        with self.driver.session() as session:
            result = session.run(query, params)
            return [record.data() for record in result]


# Natural Language to Cypher Converter
class NLToCypherConverter:
    def __init__(self, llm=None):
        self.llm = llm or ChatOpenAI(
            temperature=0,
            model="gpt-4o",
            api_key=OPENAI_API_KEY
        )

        # self.llm = ChatGoogleGenerativeAI(
        #     model = "gemini-2.5-pro-exp-03-25",
        #     temperature=0,
        #     api_key= GEMINI_API_KEY
        # )

        # self.llm = ChatGroq(temperature=0, groq_api_key=GROQ_API_KEY, model_name="llama3-70b-8192")

        
        self.prompt_template = PromptTemplate(
            input_variables=["schema", "question"],
            template="""You are a cybersecurity expert who translates natural language questions into Neo4j Cypher queries.

                 ### Database Schema:
                    {schema}

                 ### Important Notes
                 1. Service names (like SSH, HTTP, RDP) are ALWAYS stored in UPPERCASE.
                 2. Boolean properties like "is_open" are stored as true/false values.
                 3. Asset types include "server", "workstation", and "network".

                 ### Question to Convert:
                    {question}

                 ### Instructions
                 - Create a Neo4j Cypher query that answers this question
                 - Match relationship directions correctly

                 ### Examples
                 Question: "Show me all instances with SSH port open"
                 Cypher: MATCH (a:Asset)-[:HAS_PORT]->(p:Port) WHERE p.service = "SSH" AND p.is_open = true RETURN a.name AS AssetName, a.ip AS IPAddress, p.number AS PortNumber
             """
        )
    
    def get_schema(self, db):
        nodes_query = """
        CALL apoc.meta.schema()
        YIELD value
        RETURN value
        """
        schema_result = db.run_query(nodes_query)
        
        # Format the schema for the prompt
        schema_text = "Node labels and properties:\n"
        for result in schema_result:
            schema_data = result['value']  # Access the 'value' key directly
            
            # Process node types (Asset, Port, Vulnerability)
            for node_type, node_info in schema_data.items():
                if node_info.get('type') == 'node':  # Check if it's a node
                    properties = node_info.get('properties', {})
                    schema_text += f"- {node_type}: {list(properties.keys())}\n"
            
            schema_text += "\nRelationship types:\n"
            # Process relationship types (HAS_PORT, HAS_VULNERABILITY)
            for rel_type, rel_info in schema_data.items():
                if rel_info.get('type') == 'relationship':  # Check if it's a relationship
                    schema_text += f"- {rel_type}: {rel_info.get('properties', {})}\n"
            
            # Add relationship directions for better context
            schema_text += "\nRelationship directions:\n"
            for node_type, node_info in schema_data.items():
                if node_info.get('type') == 'node':
                    for rel_name, rel_details in node_info.get('relationships', {}).items():
                        direction = rel_details.get('direction', '')
                        target_labels = rel_details.get('labels', [])
                        if direction == 'out':
                            schema_text += f"- ({node_type})-[:{rel_name}]->({', '.join(target_labels)})\n"
                        elif direction == 'in':
                            schema_text += f"- ({', '.join(target_labels)})-[:{rel_name}]->({node_type})\n"
        
        return schema_text
    
    def convert_to_cypher(self, question, db):
        schema = self.get_schema(db)
        # print("SCHEMA: ",schema)
        prompt = self.prompt_template.format(schema=schema, question=question)
        # print("PROMPT: ",prompt)
        result = self.llm.invoke(prompt)
        cypher_query = result.content.strip()
        
        match = re.search(r'```.*?\n(.*?)```', cypher_query, re.DOTALL)
        if match:
            return match.group(1).strip()
    
        return f"MATCH (a:Asset) RETURN a.name LIMIT 10"


# Sample cybersecurity data generator
def create_sample_cybersecurity_data(db):
    # Create assets (servers, workstations, etc.)
    assets = [
        {"name": "web-server-01", "ip": "192.168.1.10", "type": "server"},
        {"name": "db-server-01", "ip": "192.168.1.11", "type": "server"},
        {"name": "jump-server", "ip": "192.168.1.12", "type": "server"},
        {"name": "workstation-01", "ip": "192.168.1.100", "type": "workstation"},
        {"name": "workstation-02", "ip": "192.168.1.101", "type": "workstation"},
        {"name": "firewall-01", "ip": "192.168.1.1", "type": "network"},
        {"name": "router-01", "ip": "192.168.1.2", "type": "network"}
    ]
    
    for asset in assets:
        db.create_asset(asset["name"], asset["ip"], asset["type"])
    
    # Create ports and services
    ports = [
        {"asset": "web-server-01", "port": 22, "service": "SSH", "open": True},
        {"asset": "web-server-01", "port": 80, "service": "HTTP", "open": True},
        {"asset": "web-server-01", "port": 443, "service": "HTTPS", "open": True},
        {"asset": "db-server-01", "port": 22, "service": "SSH", "open": True},
        {"asset": "db-server-01", "port": 5432, "service": "PostgreSQL", "open": True},
        {"asset": "jump-server", "port": 22, "service": "SSH", "open": True},
        {"asset": "jump-server", "port": 3389, "service": "RDP", "open": False},
        {"asset": "workstation-01", "port": 445, "service": "SMB", "open": True},
        {"asset": "workstation-02", "port": 22, "service": "SSH", "open": False},
        {"asset": "workstation-02", "port": 3389, "service": "RDP", "open": True},
        {"asset": "firewall-01", "port": 22, "service": "SSH", "open": True},
        {"asset": "firewall-01", "port": 443, "service": "HTTPS", "open": True},
        {"asset": "router-01", "port": 22, "service": "SSH", "open": True},
        {"asset": "router-01", "port": 161, "service": "SNMP", "open": True}
    ]
    
    for port_info in ports:
        db.create_port(port_info["asset"], port_info["port"], port_info["service"], port_info["open"])
    
    # Create vulnerabilities
    vulnerabilities = [
        {
            "name": "CVE-2021-3156", 
            "description": "Sudo heap-based buffer overflow", 
            "cvss": 7.8,
            "service": "SSH"
        },
        {
            "name": "CVE-2021-44228", 
            "description": "Log4j remote code execution (Log4Shell)", 
            "cvss": 10.0,
            "service": "HTTP"
        },
        {
            "name": "CVE-2019-9670", 
            "description": "Zimbra XML external entity injection", 
            "cvss": 8.8,
            "service": "HTTPS"
        },
        {
            "name": "CVE-2019-0708", 
            "description": "BlueKeep RDP vulnerability", 
            "cvss": 9.8,
            "service": "RDP"
        },
        {
            "name": "CVE-2020-0796", 
            "description": "SMBGhost vulnerability", 
            "cvss": 10.0,
            "service": "SMB"
        },
        {
            "name": "CVE-2019-11477", 
            "description": "TCP SACK Panic vulnerability", 
            "cvss": 7.5,
            "service": "PostgreSQL"
        },
        {
            "name": "CVE-2020-3452", 
            "description": "Cisco ASA/FTD path traversal vulnerability", 
            "cvss": 7.5,
            "service": "HTTPS"
        }
    ]
    
    for vuln in vulnerabilities:
        db.create_vulnerability(vuln["name"], vuln["description"], vuln["cvss"], vuln["service"])
    
    # Link vulnerabilities to specific ports
    vulnerability_mappings = [
        {"vuln": "CVE-2021-3156", "asset": "web-server-01", "port": 22},
        {"vuln": "CVE-2021-3156", "asset": "db-server-01", "port": 22},
        {"vuln": "CVE-2021-3156", "asset": "jump-server", "port": 22},
        {"vuln": "CVE-2021-44228", "asset": "web-server-01", "port": 80},
        {"vuln": "CVE-2019-9670", "asset": "web-server-01", "port": 443},
        {"vuln": "CVE-2019-0708", "asset": "workstation-02", "port": 3389},
        {"vuln": "CVE-2020-0796", "asset": "workstation-01", "port": 445},
        {"vuln": "CVE-2019-11477", "asset": "db-server-01", "port": 5432},
        {"vuln": "CVE-2020-3452", "asset": "firewall-01", "port": 443}
    ]
    
    for mapping in vulnerability_mappings:
        db.link_vulnerability_to_port(mapping["vuln"], mapping["asset"], mapping["port"])


# Main RAG application
class CybersecurityRAG:
    def __init__(self):
        self.db = Neo4jDatabase(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        self.converter = NLToCypherConverter()
    
    def setup_database(self):
        print("Setting up Neo4j database with sample cybersecurity data...")
        create_sample_cybersecurity_data(self.db)
        print("Database setup complete!")
    
    def query(self, natural_language_query):
        print(f"Processing query: {natural_language_query}")
        
        # Convert to Cypher
        cypher_query = self.converter.convert_to_cypher(natural_language_query, self.db)
        print(f"Generated Cypher: {cypher_query}")
        
        # Execute the query
        results = self.db.run_query(cypher_query)
        
        return {
            "original_query": natural_language_query,
            "cypher_query": cypher_query,
            "results": results
        }
    
    def close(self):
        self.db.close()


# Example usage
if __name__ == "__main__":
    rag = CybersecurityRAG()
    
    # Set up database (only needed once)
    try:
        rag.setup_database()
    except Exception as e:
        print(f"Database may already be set up: {e}")
    
    # Example queries
    example_queries = [
        "Show me all instances with SSH port open",
        "Find all assets with vulnerabilities having CVSS score greater than 9",
        "Which servers have RDP enabled?",
        "Show me all vulnerable services on the web server",
        "List all assets with open ports",
        "Which assets are vulnerable to Log4Shell?",
        "What is the most common vulnerability in our network?",
        "Show me network devices with SNMP enabled"
    ]
    
    # Run example queries
    for query in example_queries:
        try:
            result = rag.query(query)
            print(f"\nQuery: {result['original_query']}")
            print(f"Cypher: {result['cypher_query']}")
            print("Results:")
            for item in result['results']:
                print(f"  {item}")
        except Exception as e:
            print(f"Error processing query '{query}': {e}")
    
    rag.close()