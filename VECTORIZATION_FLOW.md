# Vectorization Flow in the Android Scanner

This document explains the complete vectorization process - how code gets converted into vectors for the RAG system.

## 🔄 **Complete Vectorization Flow**

### **1. Code Processing** (`src/processing/code_processor.py`)

**Input**: Raw source code files  
**Output**: Text chunks with metadata  

```python
# CodeProcessor.process_codebase()
def process_codebase(self):
    file_paths = self.repo_manager.get_file_paths()  # Get all files
    all_chunks = []
    
    for file_path in file_paths:
        relative_path = os.path.relpath(file_path, repo_dir)
        file_chunks = self.chunk_code_file(file_path, relative_path)
        all_chunks.extend(file_chunks)
    
    return all_chunks  # List of Document objects
```

**Each chunk contains:**
```python
Document(
    page_content="actual code content here...",
    metadata={
        'file_path': '/full/path/to/file.java',
        'relative_path': 'src/main/java/MainActivity.java',
        'language': 'java',
        'token_count': 150,
        'source': 'ast'  # or 'recursive'
    }
)
```

### **2. Vectorization** (`src/database/vector_db.py`)

**Input**: Text chunks from CodeProcessor  
**Output**: Vector embeddings stored in ChromaDB  

```python
# CodeVectorDatabase.index_code_chunks()
def index_code_chunks(self, code_chunks):
    # Convert text chunks to vectors using embedding model
    self.vector_db = Chroma.from_documents(
        documents=code_chunks,           # Text chunks
        embedding=self.embedding_model,  # PyTorch embedding model
        persist_directory=self.persist_directory,
        collection_name=self.COLLECTION_NAME
    )
    return total_indexed_count
```

### **3. Embedding Model** (`src/database/pytorch_embeddings.py`)

**Default Model**: `all-MiniLM-L6-v2` (384 dimensions)  
**Process**: Text → Vector embeddings  

```python
# Text gets converted to 384-dimensional vectors
"public void onCreate(Bundle savedInstanceState)" 
    ↓ (embedding model)
[0.1234, -0.5678, 0.9012, ..., 0.3456]  # 384 numbers
```

## 📊 **Step-by-Step Process**

### **Step 1: File Discovery & Filtering**
```python
# RepositoryManager finds relevant files
file_paths = repo_manager.get_file_paths()
# Filters out: node_modules, .git, build/, test files, etc.
```

### **Step 2: Code Chunking**
```python
# Two chunking strategies:

# A) AST-based chunking (preferred)
chunks = _chunk_code_with_ast(content, language, file_path, relative_path)
# Splits at: class_declaration, method_declaration, etc.

# B) Recursive chunking (fallback)
splitter = RecursiveCharacterTextSplitter(
    chunk_size=32000,
    chunk_overlap=1000
)
chunks = splitter.create_documents([content], [metadata])
```

### **Step 3: Text → Vectors**
```python
# PyTorch embedding model converts text to vectors
embedding_model = PyTorchEmbeddings(
    model_name="all-MiniLM-L6-v2",
    device="auto",
    dimension=384
)

# Each code chunk becomes a 384-dimensional vector
vector = embedding_model.embed_query("your code chunk text")
```

### **Step 4: Vector Storage**
```python
# ChromaDB stores vectors with metadata
vector_db = Chroma.from_documents(
    documents=code_chunks,
    embedding=embedding_model,
    persist_directory="./vector_dbs/code_db_project"
)
```

### **Step 5: Retrieval & Filtering**
```python
# Semantic search finds similar code
results = vector_db.similarity_search(
    query="deeplink intent handling onCreate",
    k=50
)

# Python filtering for filename matching
filtered = [chunk for chunk in results 
           if chunk.metadata['relative_path'].endswith('MainActivity.java')]
```

## 🔧 **Where Vectorization Happens**

### **Primary Location: ChromaDB's `from_documents()`**
```python
# In src/database/vector_db.py, line ~80
self.vector_db = Chroma.from_documents(
    documents=current_batch_docs,        # Your code chunks
    embedding=self.embedding_model,      # PyTorch model
    persist_directory=self.persist_directory,
    collection_name=self.COLLECTION_NAME
)
```

**This single call:**
1. Takes your text chunks
2. Runs them through the embedding model
3. Converts text to 384-dim vectors
4. Stores vectors + metadata in ChromaDB
5. Creates searchable index

### **Embedding Model Configuration**
```python
# In src/database/pytorch_embeddings.py
class PyTorchEmbeddings:
    def __init__(self, model_name="all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        
    def embed_documents(self, texts):
        # This is where text becomes vectors
        embeddings = self.model.encode(texts, convert_to_tensor=True)
        return embeddings.cpu().numpy()
```

## 🏗️ **Architecture Overview**

```
Source Code Files
       ↓
   CodeProcessor  ← Chunks text (AST or recursive)
       ↓
  Text Chunks + Metadata
       ↓
   PyTorchEmbeddings  ← Converts text to vectors
       ↓
   384-dim Vectors
       ↓
    ChromaDB  ← Stores vectors + enables search
       ↓
  Vector Database (Searchable)
```

## 🎯 **Key Files for Vectorization**

1. **`src/processing/code_processor.py`** - Text chunking
2. **`src/database/pytorch_embeddings.py`** - Text → Vector conversion  
3. **`src/database/vector_db.py`** - Vector storage & retrieval
4. **`src/orchestrator.py`** - Orchestrates the whole process

## 📝 **Example: MainActivity.java → Vectors**

```java
// Input: MainActivity.java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        Uri data = intent.getData();
        // ... more code
    }
}
```

```python
# 1. CodeProcessor chunks this into smaller pieces
chunk1 = Document(
    page_content="public class MainActivity extends AppCompatActivity {",
    metadata={'relative_path': 'MainActivity.java', 'language': 'java'}
)

chunk2 = Document(
    page_content="protected void onCreate(Bundle savedInstanceState) {\n    Intent intent = getIntent();\n    Uri data = intent.getData();",
    metadata={'relative_path': 'MainActivity.java', 'language': 'java'}
)

# 2. PyTorchEmbeddings converts to vectors
vector1 = [0.1234, -0.5678, 0.9012, ..., 0.3456]  # 384 dimensions
vector2 = [0.2345, -0.6789, 0.1023, ..., 0.4567]  # 384 dimensions

# 3. ChromaDB stores vectors + metadata for search
# Now you can search: "deeplink intent handling" → finds chunk2
```

The vectorization happens **automatically** when you call `vector_db.index_code_chunks(code_chunks)` in the orchestrator!
