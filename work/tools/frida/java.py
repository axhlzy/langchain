from typing import Type, Any

from pydantic import BaseModel
from pydantic import Field

from langchain import PromptTemplate
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import FewShotPromptTemplate

from langchain.tools import BaseTool


class generate_java_hook_code_input(BaseModel):
    """Inputs for generate_java_hook_code"""
    des: str = Field(description="Description of the hook code to be generated")


class generate_java_hook_code(BaseTool):
    name = "generate_java_hook_code"
    description = """生成 frida hook java 的 hook 的 js 代码"""
    args_schema: Type[BaseModel] = generate_java_hook_code_input
    prompt = PromptTemplate.from_template("""
                You are now a senior programmer proficient in Frida's API I hope you can help me write a code that uses 
                frida to hook java. For example, I want to hook java's startActivity method to monitor the start of the 
                activity and print the stack, information for me at the same time. You should generate the code in the 
                following format, and only return this part of the code without any other content.
                the code part is between >>> and <<< 
                >>>
                rpc.exports = {{
                    tmpFunction: function () {{
                        if (Java.available) {{
                            Java.perform(function () {{
                                var Activity = Java.use('android.app.Activity');
                                Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {{
                                    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
                                    console.log('Starting activity: ' + intent);
                                    this.startActivity.overload('android.content.Intent').call(this, intent);
                                }};
                            }});
                            return 'Success to hook startActivity.'
                        }} else {{
                            console.error('Java is not available.');
                            return 'Java is not available.'
                        }}
                    }}
                }}
                <<<
                now my question is:
                {input_message}
            """)

    def _run(self, des: str, *args: Any) -> Any:
        llm_chain = LLMChain(llm=OpenAI(), prompt=self.prompt)
        return llm_chain.run(input_message=des)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        pass