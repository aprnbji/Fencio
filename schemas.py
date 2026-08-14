from pydantic import BaseModel 

class ReconResult(BaseModel):
    capabilities: str = ""
    tools: str = ""
    restrictions: str = ""
    external_access: str = ""
    system_prompt: str = ""
    knowledge: str = ""
    purpose: str = ""
    data_access: str = ""
    code_execution: str = ""
    file_operations: str = ""
