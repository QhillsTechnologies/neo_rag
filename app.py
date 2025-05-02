import streamlit as st

# Page configuration must be the first Streamlit command
st.set_page_config(
    page_title="Cybersecurity Neo4j RAG",
    page_icon="🔒",
    layout="wide"
)

import pandas as pd
import json
from dotenv import load_dotenv
import os
import sys

# Load environment variables from .env file
load_dotenv()

# Import our CybersecurityRAG class
# Since we're now using a flatter file structure, we can import directly
from cyber_sec import CybersecurityRAG

# Initialize the RAG system
@st.cache_resource
def get_rag_system():
    return CybersecurityRAG()

rag = get_rag_system()

# Title and description
st.title("🔒 Cybersecurity Neo4j RAG System")
st.markdown("""
This application allows you to query cybersecurity data stored in a Neo4j graph database using natural language.
Simply type your question, and the system will convert it to a Cypher query and retrieve the relevant information.
""")

# Example queries that users can select
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

# Sidebar for example queries
st.sidebar.header("Example Queries")
selected_example = st.sidebar.selectbox(
    "Select an example query:",
    [""] + example_queries
)

# Main query input
query = st.text_input("Enter your cybersecurity query:", value=selected_example)

# Database setup button (with confirmation)
if st.sidebar.button("Setup Sample Database"):
    with st.spinner("Setting up Neo4j database with sample cybersecurity data..."):
        try:
            rag.setup_database()
            st.sidebar.success("Database setup complete!")
        except Exception as e:
            st.sidebar.error(f"Error: {str(e)}")
            st.sidebar.info("If the database is already set up, you can ignore this error.")

# Process the query when submitted
if query:
    with st.spinner("Processing your query..."):
        try:
            # Execute the query
            result = rag.query(query)
            
            # Display the Cypher query
            st.subheader("Generated Cypher Query")
            st.code(result["cypher_query"], language="cypher")
            
            # Display the results
            st.subheader("Results")
            
            if not result["results"]:
                st.info("No results found for this query.")
            else:
                # Convert to DataFrame for better display
                try:
                    # Handle different result structures
                    flattened_results = []
                    for item in result["results"]:
                        flat_item = {}
                        for key, value in item.items():
                            if isinstance(value, dict):
                                for subkey, subvalue in value.items():
                                    flat_item[f"{key}.{subkey}"] = subvalue
                            else:
                                flat_item[key] = value
                        flattened_results.append(flat_item)
                    
                    df = pd.DataFrame(flattened_results)
                    st.dataframe(df)
                except Exception as e:
                    # Fall back to raw display if DataFrame conversion fails
                    st.json(result["results"])
            
            # Visualization section (only if results are present)
            if result["results"]:
                st.subheader("Graph Visualization")
                st.info("To view the full graph visualization, access the Neo4j Browser at http://localhost:7474")
                
                # Display a code snippet to view this in Neo4j Browser
                browser_query = result["cypher_query"].replace("\n", " ").strip()
                st.code(f"// Open Neo4j Browser and paste this query:\n{browser_query}", language="cypher")
        
        except Exception as e:
            st.error(f"Error: {str(e)}")

# Add information about the database schema
with st.sidebar.expander("Database Schema"):
    st.markdown("""
    **Node Labels:**
    - Asset: network assets (servers, workstations, etc.)
    - Port: network ports and services
    - Vulnerability: security vulnerabilities (CVEs)
    
    **Relationships:**
    - (Asset)-[:HAS_PORT]->(Port)
    - (Port)-[:HAS_VULNERABILITY]->(Vulnerability)
    
    **Key Properties:**
    - Asset: name, ip, type
    - Port: number, service, is_open
    - Vulnerability: name, description, cvss, affected_service
    """)

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("© 2025 Cybersecurity Neo4j RAG System")