# Dependency & Security Analysis Report
Generated: 2025-07-05 15:55:26

## 📊 Summary
- **Files Analyzed**: 2
- **Total Dependencies**: 67
- **Security Vulnerabilities**: 0
- **License Types**: 13

### 📜 License Distribution
- **bsd-3-clause**: 3 packages
- **mit**: 23 packages
- **mit license**: 1 packages
- **mpl-2.0**: 1 packages
- **apache license, version 2.0**: 1 packages
- **bsd 3-clause license
        
        copyright (c) 2018, martin durant
        all rights reserved.
        
        redistribution and use in source and binary forms, with or without
        modification, are permitted provided that the following conditions are met:
        
        * redistributions of source code must retain the above copyright notice, this
          list of conditions and the following disclaimer.
        
        * redistributions in binary form must reproduce the above copyright notice,
          this list of conditions and the following disclaimer in the documentation
          and/or other materials provided with the distribution.
        
        * neither the name of the copyright holder nor the names of its
          contributors may be used to endorse or promote products derived from
          this software without specific prior written permission.
        
        this software is provided by the copyright holders and contributors "as is"
        and any express or implied warranties, including, but not limited to, the
        implied warranties of merchantability and fitness for a particular purpose are
        disclaimed. in no event shall the copyright holder or contributors be liable
        for any direct, indirect, incidental, special, exemplary, or consequential
        damages (including, but not limited to, procurement of substitute goods or
        services; loss of use, data, or profits; or business interruption) however
        caused and on any theory of liability, whether in contract, strict liability,
        or tort (including negligence or otherwise) arising in any way out of the use
        of this software, even if advised of the possibility of such damage.**: 1 packages
- **apache-2.0**: 2 packages
- **apache**: 1 packages
- **expat license**: 1 packages
- **bsd-2-clause**: 1 packages
- **mit or apache-2.0**: 1 packages
- **mit license  copyright (c) 2021 taneli hukkinen  permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "software"), to deal in the software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, and to permit persons to whom the software is furnished to do so, subject to the following conditions:  the above copyright notice and this permission notice shall be included in all copies or substantial portions of the software.  the software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. in no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. **: 1 packages
- **mpl-2.0 and mit**: 1 packages

## 📋 Detailed Analysis

### 1. pyproject.toml
**Package Manager**: poetry/setuptools
**File Path**: `/Users/beauxwalton/wtf-codebot/pyproject.toml`

#### Dependencies
| Package | Version | Type | License |
|---------|---------|------|---------|
| click | ^8.1.7 | prod | Unknown |
| typer | ^0.9.0 | prod | Unknown |
| pydantic | ^2.5.0 | prod | Unknown |
| python-dotenv | ^1.0.0 | prod | BSD-3-Clause |
| anthropic | ^0.8.0 | prod | MIT |
| rich | ^13.7.0 | prod | MIT |
| pyyaml | ^6.0.1 | prod | MIT |
| structlog | ^23.2.0 | prod | Unknown |
| beautifulsoup4 | ^4.12.0 | prod | MIT License |
| cssutils | ^2.9.0 | prod | Unknown |
| tree-sitter | ^0.20.0 | prod | Unknown |
| tree-sitter-python | ^0.20.0 | prod | MIT |
| tree-sitter-javascript | ^0.20.0 | prod | MIT |
| tree-sitter-typescript | ^0.20.0 | prod | MIT |
| toml | ^0.10.2 | prod | MIT |
| pytest | ^7.4.3 | dev | MIT |
| black | ^23.11.0 | dev | Unknown |
| isort | ^5.12.0 | dev | Unknown |
| flake8 | ^6.1.0 | dev | MIT |
| mypy | ^1.7.0 | dev | MIT |

#### ✅ No vulnerabilities found

---

### 2. poetry.lock
**Package Manager**: poetry
**File Path**: `/Users/beauxwalton/wtf-codebot/poetry.lock`

#### Dependencies
| Package | Version | Type | License |
|---------|---------|------|---------|
| annotated-types | 0.7.0 | prod | Unknown |
| anthropic | 0.8.1 | prod | MIT |
| anyio | 4.5.2 | prod | MIT |
| black | 23.12.1 | prod | Unknown |
| certifi | 2025.6.15 | prod | MPL-2.0 |
| charset-normalizer | 3.4.2 | prod | MIT |
| click | 8.1.8 | prod | Unknown |
| colorama | 0.4.6 | prod | Unknown |
| distro | 1.9.0 | prod | Apache License, Version 2.0 |
| exceptiongroup | 1.3.0 | prod | Unknown |
| filelock | 3.16.1 | prod | Unknown |
| flake8 | 6.1.0 | prod | MIT |
| fsspec | 2025.3.0 | prod | BSD 3-Clause License
        
        Copyright (c) 2018, Martin Durant
        All rights reserved.
        
        Redistribution and use in source and binary forms, with or without
        modification, are permitted provided that the following conditions are met:
        
        * Redistributions of source code must retain the above copyright notice, this
          list of conditions and the following disclaimer.
        
        * Redistributions in binary form must reproduce the above copyright notice,
          this list of conditions and the following disclaimer in the documentation
          and/or other materials provided with the distribution.
        
        * Neither the name of the copyright holder nor the names of its
          contributors may be used to endorse or promote products derived from
          this software without specific prior written permission.
        
        THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
        AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
        IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
        DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
        FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
        DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
        SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
        CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
        OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
        OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. |
| h11 | 0.16.0 | prod | MIT |
| hf-xet | 1.1.5 | prod | Apache-2.0 |
| httpcore | 1.0.9 | prod | Unknown |
| httpx | 0.28.1 | prod | BSD-3-Clause |
| huggingface-hub | 0.33.2 | prod | Apache |
| idna | 3.10 | prod | Unknown |
| iniconfig | 2.1.0 | prod | Unknown |
| isort | 5.13.2 | prod | Unknown |
| markdown-it-py | 3.0.0 | prod | Unknown |
| mccabe | 0.7.0 | prod | Expat license |
| mdurl | 0.1.2 | prod | Unknown |
| mypy | 1.14.1 | prod | MIT |
| mypy-extensions | 1.1.0 | prod | Unknown |
| packaging | 25.0 | prod | Unknown |
| pathspec | 0.12.1 | prod | Unknown |
| platformdirs | 4.3.6 | prod | Unknown |
| pluggy | 1.5.0 | prod | MIT |
| pycodestyle | 2.11.1 | prod | MIT |
| pydantic | 2.10.6 | prod | Unknown |
| pydantic-core | 2.27.2 | prod | MIT |
| pyflakes | 3.1.0 | prod | MIT |
| pygments | 2.19.2 | prod | BSD-2-Clause |
| pytest | 7.4.4 | prod | MIT |
| python-dotenv | 1.0.1 | prod | BSD-3-Clause |
| pyyaml | 6.0.2 | prod | MIT |
| requests | 2.32.4 | prod | Apache-2.0 |
| rich | 13.9.4 | prod | MIT |
| sniffio | 1.3.1 | prod | MIT OR Apache-2.0 |
| structlog | 23.3.0 | prod | Unknown |
| tokenizers | 0.21.0 | prod | Unknown |
| tomli | 2.2.1 | prod | MIT License  Copyright (c) 2021 Taneli Hukkinen  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  |
| tqdm | 4.67.1 | prod | MPL-2.0 AND MIT |
| typing-extensions | 4.13.2 | prod | Unknown |
| urllib3 | 2.2.3 | prod | Unknown |

#### ✅ No vulnerabilities found

---

## 💡 Recommendations
- 📜 29 dependencies have unknown licenses. Review for compliance.
- 🔄 Regularly update dependencies to latest stable versions.
- 🛡️ Set up automated security scanning in your CI/CD pipeline.
- 📊 Monitor dependency health with tools like Dependabot or Renovate.
- 🏷️ Use semantic versioning and pin critical dependency versions.
- 📋 Maintain a software bill of materials (SBOM) for compliance.
