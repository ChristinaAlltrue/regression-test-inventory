#  Copyright 2023-2024 AllTrue.ai Inc
#  All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains
#  the property of AllTrue.ai Incorporated. The intellectual and technical
#  concepts contained herein are proprietary to AllTrue.ai Incorporated
#  and may be covered by U.S. and Foreign Patents,
#  patents in process, and are protected by trade secret or copyright law.
#  Dissemination of this information or reproduction of this material
#  is strictly forbidden unless prior written permission is obtained
#  from AllTrue.ai Incorporated.
import io
from collections import Counter
from uuid import UUID

import nvdlib
import pytest
from sqlalchemy import text

from app.api.services.services import handle_project_reassignments
from app.core.db.engine import get_db_session
from app.core.db.model_utils.resource_instance_model_utils import (
    get_resource_instance_by_id,
)
from app.core.db.models.ai_inventory_item import DependencyFileUpload, ResourceInstance
from app.core.db.models.resource_source import ResourceSource
from app.core.schemas.inventory.enums import LanguageAndFile, ResourceActive
from app.utils.inventory.ai_inventory_supported_libraries import process_dependency_file
from app.utils.onboarding.default_hierarchy import customer_default_project_id
from app.utils.posture_management.cves.nvd_key import retrieve_nvd_key
from app.utils.posture_management.cves.search_cpe import (
    clean_name_and_version_of_library,
)
from tests.factories.project import ProjectFactory


@pytest.fixture
def db_session():
    with get_db_session() as session:
        yield session


@pytest.fixture
def requirements_txt():
    return {
        "filename": "requirements.txt",
        "content": """
            # This file is auto-generated from environment.yml, do not modify.
            # See that file for comments about the need/usage of each dependency.

            pip
            versioneer[toml]
            cython~=3.0.5
            meson[ninja]==1.2.1
            meson-python==0.13.1
            pytest>=7.3.2
            pytest-cov
            pytest-xdist>=2.2.0
            pytest-qt>=4.2.0
            pytest-localserver
            PyQt5>=5.15.9
            coverage
            python-dateutil
            numpy<2
            pytz
            beautifulsoup4>=4.11.2
            blosc
            bottleneck>=1.3.6
            fastparquet>=2023.10.0
            fsspec>=2022.11.0
            html5lib>=1.1
            hypothesis>=6.46.1
            gcsfs>=2022.11.0
            ipython
            jinja2>=3.1.2
            lxml>=4.9.2
            random-library-not-in-registry>=3.6.3
            numba>=0.56.4
            numexpr>=2.8.4
            openpyxl>=3.1.0
            odfpy>=1.4.1
            py
            psycopg2-binary>=2.9.6
            pyarrow>=10.0.1
            pymysql>=1.0.2
            pyreadstat>=1.2.0
            tables>=3.8.0
            python-calamine>=0.1.7
            pyxlsb>=1.0.10
            s3fs>=2022.11.0
            scipy>=1.10.0
            SQLAlchemy>=2.0.0
            tabulate>=0.9.0
            xarray>=2022.12.0
            xlrd>=2.0.1
            xlsxwriter>=3.0.5
            zstandard>=0.19.0
            dask
            seaborn
            moto
            flask
            asv>=0.6.1
            flake8==6.1.0
            mypy==1.9.0
            tokenize-rt
            pre-commit>=3.6.0
            gitpython
            gitdb
            google-auth
            natsort
            numpydoc
            pydata-sphinx-theme==0.14
            pytest-cython
            sphinx
            sphinx-design
            sphinx-copybutton
            types-python-dateutil
            types-PyMySQL
            types-pytz
            types-PyYAML
            types-setuptools
            nbconvert>=7.11.0
            nbsphinx
            pandoc
            ipywidgets
            nbformat
            notebook>=7.0.6
            ipykernel
            markdown
            feedparser
            pyyaml
            requests
            pygments
            adbc-driver-postgresql>=0.10.0
            adbc-driver-sqlite>=0.8.0
            typing_extensions; python_version<"3.11"
            tzdata>=2022.7
            albumentations
            alltrue @ git+ssh://git@github.com/AllTrue-ai/ai-security-python-api.git@4572d171e2bc41c4aafab4cf1a3bff2efd893b24
        """,
    }


@pytest.fixture
def requirements_txt_hash():
    return {
        "filename": "requirements.txt",
        "content": """
            # This file is auto-generated from environment.yml, do not modify.
            # See that file for comments about the need/usage of each dependency.
            alltrue @ git+ssh://git@github.com/AllTrue-ai/ai-security-python-api.git@4572d171e2bc41c4aafab4cf1a3bff2efd893b24
            alltrue-2 @ git+ssh://git@github.com/AllTrue-ai/ai-security-python-api.git@4572d171e2bc41c4aafab4cf1a3bff2efd893b29
        """,
    }


@pytest.fixture
def requirements_txt_result():
    return [
        ("numpy", "2"),
        ("pyarrow", "10.0.1"),
        ("scipy", "1.10.0"),
        ("dask", None),
        ("seaborn", None),
        ("notebook", "7.0.6"),
        ("albumentations", None),
    ]


@pytest.fixture
def dependency_file_identifier() -> str:
    return "test-dependency-file-identifier-1"


@pytest.fixture
def project_id(customer_id) -> UUID:
    return ProjectFactory(customer_id=customer_id).project_id


@pytest.fixture
def project_id2(customer_id) -> UUID:
    return ProjectFactory(customer_id=customer_id).project_id


@pytest.fixture
def project_id3(customer_id) -> UUID:
    return ProjectFactory(customer_id=customer_id).project_id


@pytest.fixture
def api_key(openai_api_key) -> str:
    return openai_api_key


@pytest.fixture
def endpoint_identifier() -> str:
    return "test-endpoint-string"


@pytest.fixture
def dependency_file_post_call(customer_id, db_session):
    yield f"/v1/inventory/customer/{customer_id}/resources/dependency-file"
    db_session.query(ResourceInstance).filter(
        ResourceInstance.customer_id == customer_id
    ).delete(synchronize_session="fetch")
    db_session.query(DependencyFileUpload).filter(
        DependencyFileUpload.customer_id == customer_id
    ).delete(synchronize_session="fetch")


@pytest.fixture
def resource_setup(
    api_key,
    endpoint_identifier,
):
    resource_properties = {
        "api_key": api_key,
        "endpoint_identifier": endpoint_identifier,
    }

    body = {
        "resources": [
            {
                "resource_type": "OpenAIEndpoint",
                "resource_data": resource_properties,
                "technology_types": ["openai-api-key"],
            }
        ]
    }

    yield body


@pytest.fixture
def query_params():
    return {
        "python_requirements": LanguageAndFile.PYTHON_REQUIREMENTS_TXT.value,
        "python_environment": LanguageAndFile.PYTHON_ENVIRONMENT_YML.value,
        "python_dockerfile": LanguageAndFile.PYTHON_DOCKERFILE.value,
    }


@pytest.mark.integration
def test_requirements_parsing_dynamic_commit_hash_based(
    client,
    dependency_file_post_call,
    requirements_txt_hash,
    resource_setup,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
    customer_id,
):
    file = io.BytesIO(requirements_txt_hash["content"].encode("utf-8"))
    file.filename = "requirements.txt"
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200


@pytest.mark.integration
def test_requirements_upload_dependencies_api_call(
    client,
    dependency_file_post_call,
    requirements_txt,
    requirements_txt_result,
    resource_setup,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
    customer_id,
):
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    # First, we add a dependency file and the resources to db
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )

    assert response.status_code == 200

    # Convert the list of lists to a list of tuples cuz in the response, tuples are converted to lists during
    # serialization
    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # --------------------------------------------------------------------------
    # Incorrect language and file, so nothing should happen to existing resources and dependency file.
    bad_response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": "python_environment",
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("environment.txt", file, "text/plain")},
    )
    assert bad_response.status_code == 422  # an error is raised from enum validation

    # Check dependency_file_upload table is not empty and previous upload still active
    rows = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload where customer_id=:customer_id"
        ).bindparams(
            customer_id=customer_id,
        )
    ).fetchall()
    dependency_file_upload_id = rows[0].dependency_file_upload_id
    assert len(rows) == 1
    assert rows[0].active

    # There should be 7 resources in the resource_instance table and they should be active
    rows = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == dependency_file_upload_id,
        )
        .all()
    )
    assert len(rows) >= 7

    for row in rows:
        assert row.active == ResourceActive.ACTIVE


@pytest.fixture
def environment_yml():
    return {
        "filename": "environment.yml",
        "content": """
            # Local development dependencies including docs building, website upload, ASV benchmark
            name: pandas-dev
            channels:
              - conda-forge
            dependencies:
              - python=3.10
              - pip

              # build dependencies
              - versioneer[toml]
              - cython~=3.0.5
              - meson[ninja]=1.2.1
              - meson-python=0.13.1

              # test dependencies
              - pytest>=7.3.2
              - pytest-cov
              - pytest-xdist>=2.2.0
              - pytest-qt>=4.2.0
              - pytest-localserver
              - pyqt>=5.15.9
              - coverage

              # required dependencies
              - python-dateutil
              - numpy<2
              - pytz

              # optional dependencies
              - beautifulsoup4>=4.11.2
              - blosc
              - bottleneck>=1.3.6
              - fastparquet>=2023.10.0
              - fsspec>=2022.11.0
              - html5lib>=1.1
              - hypothesis>=6.46.1
              - gcsfs>=2022.11.0
              - ipython
              - jinja2>=3.1.2
              - lxml>=4.9.2
              - random-library-not-in-registry>=3.6.3
              - numba>=0.56.4
              - numexpr>=2.8.4
              - openpyxl>=3.1.0
              - odfpy>=1.4.1
              - py
              - psycopg2>=2.9.6
              - pyarrow>=10.0.1
              - pymysql>=1.0.2
              - pyreadstat>=1.2.0
              - pytables>=3.8.0
              - python-calamine>=0.1.7
              - pyxlsb>=1.0.10
              - s3fs>=2022.11.0
              - scipy>=1.10.0
              - sqlalchemy>=2.0.0
              - seaborn>=1.11.11
              - tabulate>=0.9.0
              - xarray>=2022.12.0
              - xlrd>=2.0.1
              - xlsxwriter>=3.0.5
              - zstandard>=0.19.0
              - albumentations

              # downstream packages
              - dask-core
              - seaborn-base

              # local testing dependencies
              - moto
              - flask

              # benchmarks
              - asv>=0.6.1

              ## The compiler packages are meta-packages and install the correct compiler (activation) packages on the respective platforms.
              - c-compiler
              - cxx-compiler

              # code checks
              - flake8=6.1.0  # run in subprocess over docstring examples
              - mypy=1.9.0  # pre-commit uses locally installed mypy
              - tokenize-rt  # scripts/check_for_inconsistent_pandas_namespace.py
              - pre-commit>=3.6.0

              # documentation
              - gitpython  # obtain contributors from git for whatsnew
              - gitdb
              - google-auth
              - natsort  # DataFrame.sort_values doctest
              - numpydoc
              - pydata-sphinx-theme=0.14
              - pytest-cython  # doctest
              - sphinx
              - sphinx-design
              - sphinx-copybutton
              - types-python-dateutil
              - types-PyMySQL
              - types-pytz
              - types-PyYAML
              - types-setuptools

              # documentation (jupyter notebooks)
              - nbconvert>=7.11.0
              - nbsphinx
              - pandoc
              - ipywidgets
              - nbformat
              - notebook>=7.0.6
              - ipykernel

              # web
              # - jinja2  # already listed in optional dependencies, but documented here for reference
              - markdown
              - feedparser
              - pyyaml
              - requests
              - pygments # Code highlighting

              - pip:
                  - adbc-driver-postgresql>=0.10.0
                  - adbc-driver-sqlite>=0.8.0
                  - typing_extensions; python_version<"3.11"
                  - tzdata>=2022.7
                  - meson[ninja]==1.2.1  # added this myself
                  - allennlp
        """,
    }


@pytest.fixture
def environment_yml_result():
    return [
        ("numpy", "2"),
        ("pyarrow", "10.0.1"),
        ("notebook", "7.0.6"),
        ("scipy", "1.10.0"),
        ("seaborn", "1.11.11"),
        ("albumentations", None),
        ("allennlp", None),
    ]


@pytest.mark.integration
def test_environment_upload_dependencies_api_call(
    client,
    customer_id,
    dependency_file_post_call,
    environment_yml,
    environment_yml_result,
    resource_setup,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
):
    file = io.BytesIO(environment_yml["content"].encode("utf-8"))
    file.filename = "environment.yml"
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_environment"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )

    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(environment_yml_result)

    # Check dependency_file_upload table is not empty
    rows = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload where customer_id = :customer_id"
        ).bindparams(
            customer_id=customer_id,
        )
    ).fetchall()
    dependency_file_upload_id = rows[0].dependency_file_upload_id
    assert len(rows) == 1
    assert rows[0].active

    # Check resource_instance table is not empty

    rows = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == dependency_file_upload_id,
        )
        .all()
    )
    assert len(rows) >= 7

    for row in rows:
        assert row.active == ResourceActive.ACTIVE


@pytest.fixture
def dockerfile():
    return {
        "filename": "Dockerfile",
        "content": """
            # Author: Robin Dhillon
            FROM continuumio/miniconda3:4.12.0

            # Update apt
            RUN apt-get update
            RUN apt-get -y --no-install-recommends install

            # Install R packages
            RUN apt-get install -y r-base r-base-dev

            # Install R dependencies
            RUN apt-get install -y libxml2-dev libcurl4-openssl-dev libssl-dev libfontconfig1-dev

            RUN Rscript -e "install.packages('tidyverse', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('broom', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('docopt', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('knitr', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('kableExtra', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('caret', repos='https://cran.rstudio.com/')"
            RUN Rscript -e "install.packages('xfun', repos='https://cran.rstudio.com/')"

            ENV PATH="/opt/conda/bin:${PATH}"

            # Update conda
            RUN conda update -n base -c conda-forge -y conda

            # Install python packages
            RUN conda install -c conda-forge -y random-library-not-in-registry==4.2.0
            RUN conda install -c conda-forge -y scikit-learn>=1.1.3
            RUN conda install -c conda-forge -y lxml==4.9.2
            RUN conda install -c conda-forge -y pandoc==2.19.2

            RUN pip install joblib==1.2.0 --quiet
            RUN pip install mglearn==0.1.9 --quiet
            RUN pip install psutil==5.9.4 --quiet
            RUN pip install docopt-ng --quiet
            RUN pip install vl-convert-python --quiet
            RUN pip install albumentations --quiet
        """,
    }


@pytest.fixture
def dockerfile_result():
    return [
        ("scikit-learn", "1.1.3"),
        ("joblib", "1.2.0"),
        ("albumentations", None),
    ]


@pytest.mark.integration
def test_dockerfile_upload_dependencies_api_call(
    client,
    customer_id,
    dependency_file_post_call,
    dockerfile,
    dockerfile_result,
    resource_setup,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
):
    file = io.BytesIO(dockerfile["content"].encode("utf-8"))
    file.filename = "Dockerfile"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_dockerfile"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("Dockerfile", file, "text/plain")},
    )

    assert response.status_code == 200
    print(response.json())
    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(dockerfile_result)

    # --------------------------------------------------------------------------

    bad_response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_environment"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("dockerfile", file, "text/plain")},
    )
    assert bad_response.status_code == 200  # not raising error

    # Check dependency_file_upload table is not empty

    rows = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload where customer_id = :customer_id"
        ).bindparams(
            customer_id=customer_id,
        )
    ).fetchall()
    dependency_file_upload_id = rows[0].dependency_file_upload_id
    assert len(rows) == 1
    assert rows[0].active

    # Check resource_instance table is not empty

    rows = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == dependency_file_upload_id,
        )
        .all()
    )
    assert len(rows) >= 3

    for row in rows:
        assert row.active == ResourceActive.ACTIVE


# ------------------------------ Test versioning ---------------------------------


@pytest.fixture
def requirements_txt_less():
    return {
        "filename": "requirements.txt",
        "content": """
            numpy<2
            pyarrow>=10.0.1
            scipy==1.10.0
            dask
            seaborn
            xarray==2022.12.0
            numba==0.56.4
        """,
    }


@pytest.fixture
def requirements_txt_less_result():
    return [
        ("numpy", "2"),
        ("pyarrow", "10.0.1"),
        ("scipy", "1.10.0"),
        ("dask", None),
        ("seaborn", None),
    ]


@pytest.fixture
def requirements_txt_more():
    return {
        "filename": "requirements.txt",
        "content": """
            numpy<2
            pyarrow>=10.0.1
            scipy==1.10.0
            dask
            seaborn
            albumentations
            allennlp
        """,
    }


@pytest.fixture
def requirements_txt_more_result():
    return [
        ("numpy", "2"),
        ("pyarrow", "10.0.1"),
        ("scipy", "1.10.0"),
        ("dask", None),
        ("seaborn", None),
        ("albumentations", None),
        ("allennlp", None),
    ]


@pytest.fixture
def requirements_txt_new_libs():
    return {
        "filename": "requirements.txt",
        "content": """
            adapters<2
            aim>=10.0.1
            pyarrow==1.10.0
            autogpt
            anything-llm
            bertopic
            clearml
        """,
    }


@pytest.fixture
def requirements_txt_new_libs_result():
    return [
        ("adapters", "2"),
        ("aim", "10.0.1"),
        ("pyarrow", "1.10.0"),
        ("autogpt", None),
        ("anything-llm", None),
        ("bertopic", None),
        ("clearml", None),
    ]


@pytest.mark.integration
@pytest.mark.asyncio
def test_versioning_upload_dependencies_api_call(
    client,
    dependency_file_post_call,
    requirements_txt,
    requirements_txt_less,
    requirements_txt_more,
    requirements_txt_result,
    requirements_txt_less_result,
    requirements_txt_more_result,
    db_session,
    query_params,
    dependency_file_identifier,
    requirements_txt_new_libs,
    requirements_txt_new_libs_result,
    project_id,
    customer_id,
):
    def check_active_and_deleted_counts(active_id, deleted_id):
        active_rows = (
            db_session.query(ResourceInstance)
            .join(
                ResourceSource,
                ResourceSource.resource_instance_id
                == ResourceInstance.resource_instance_id,
            )
            .filter(
                ResourceInstance.customer_id == customer_id,
                ResourceSource.dependency_file_upload_id == active_id,
                ResourceInstance.active == ResourceActive.ACTIVE,
            )
            .all()
        )

        deleted_rows = []
        if deleted_id:
            deleted_rows = (
                db_session.query(ResourceInstance)
                .filter(
                    ResourceInstance.customer_id == customer_id,
                    ResourceInstance.active == ResourceActive.DELETED,
                    ~ResourceInstance.resource_sources.any(),  # no sources = deleted
                )
                .all()
            )

        return active_rows, deleted_rows

    # First upload
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload where customer_id = :customer_id"
        ).bindparams(customer_id=customer_id)
    ).fetchall()
    assert len(rows) == 1

    active, deleted = check_active_and_deleted_counts(
        active_id=rows[0].dependency_file_upload_id,
        deleted_id=None,
    )
    assert len(active) >= 7
    assert len(deleted) == 0

    # Second upload with two less libraries
    file = io.BytesIO(requirements_txt_less["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_less_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )

    assert len(rows) >= 2

    # Two no longer used, so set to deleted. Rest are still active
    active, deleted = check_active_and_deleted_counts(
        active_id=rows[1].dependency_file_upload_id,
        deleted_id=rows[0].dependency_file_upload_id,
    )
    import logfire

    logfire.info(
        "results_compare:",
        active=[lib.resource_identifier for lib in active],
        deleted=[lib.resource_identifier for lib in deleted],
    )
    assert len(active) == 7
    assert len(deleted) == 2  # albumentations, notebook missing

    # Third upload with one more library
    file = io.BytesIO(requirements_txt_more["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_more_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 3

    active, deleted = check_active_and_deleted_counts(
        active_id=rows[2].dependency_file_upload_id,
        deleted_id=rows[1].dependency_file_upload_id,
    )
    assert len(active) >= 7
    assert len(deleted) >= 1  # notebook missing

    # Fourth upload with new libraries
    file = io.BytesIO(requirements_txt_new_libs["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_new_libs_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) >= 4

    # All previous libraries are now deleted
    active, deleted = check_active_and_deleted_counts(
        active_id=rows[3].dependency_file_upload_id,
        deleted_id=rows[2].dependency_file_upload_id,
    )
    assert len(active) == 7
    assert len(deleted) >= 8


def check_active_and_deleted_counts_with_resources(
    db_session, customer_id, active_id, deleted_id
):
    active_rows = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == active_id,
            ResourceInstance.active == ResourceActive.ACTIVE,
        )
        .all()
    )

    deleted_rows = []
    if deleted_id:
        deleted_rows = (
            db_session.query(ResourceInstance)
            .filter(
                ResourceInstance.customer_id == customer_id,
                ResourceInstance.active == ResourceActive.DELETED,
                ~ResourceInstance.resource_sources.any(),
            )
            .all()
        )

    source_rows = (
        db_session.query(ResourceSource)
        .filter(ResourceSource.customer_id == customer_id)
        .all()
    )
    return active_rows, deleted_rows, source_rows


@pytest.mark.integration
@pytest.mark.asyncio
def test_versioning_upload_dependencies_same_file_diff_identifiers(
    client,
    dependency_file_post_call,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    project_id,
    customer_id,
):
    identifier_1 = "test-dependency-file-identifier-1"
    identifier_2 = "test-dependency-file-identifier-2"

    # First upload
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": identifier_1,
            "display_name": identifier_1,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 1

    active, deleted, sources = check_active_and_deleted_counts_with_resources(
        db_session=db_session,
        customer_id=customer_id,
        active_id=rows[0].dependency_file_upload_id,
        deleted_id=None,
    )
    assert len(active) >= 7
    assert len(deleted) == 0
    assert len(sources) >= 7

    # Second upload, same everything but different identifier
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": identifier_2,
            "display_name": identifier_2,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 2

    active, deleted, sources = check_active_and_deleted_counts_with_resources(
        db_session=db_session,
        customer_id=customer_id,
        active_id=rows[1].dependency_file_upload_id,
        deleted_id=rows[0].dependency_file_upload_id,
    )
    assert len(active) >= 7
    assert len(deleted) == 0  # None should be deleted – still linked via another file
    assert len(sources) >= 14  # 7 from identifier_1 + 7 from identifier_2


@pytest.mark.integration
@pytest.mark.asyncio
def test_versioning_upload_dependencies_same_file_diff_projects(
    client,
    dependency_file_post_call,
    dependency_file_identifier,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    project_id,
    project_id2,
    customer_id,
):
    # First upload
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 1

    active, deleted, sources = check_active_and_deleted_counts_with_resources(
        db_session=db_session,
        customer_id=customer_id,
        active_id=rows[0].dependency_file_upload_id,
        deleted_id=None,
    )
    assert len(active) >= 7
    assert len(deleted) == 0
    assert len(sources) >= 7

    # Second upload, same everything but different project
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id2,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 2

    active, deleted, sources = check_active_and_deleted_counts_with_resources(
        db_session=db_session,
        customer_id=customer_id,
        active_id=rows[1].dependency_file_upload_id,
        deleted_id=rows[0].dependency_file_upload_id,
    )
    assert len(active) >= 7
    assert len(deleted) == 0
    assert len(sources) >= 14

    # Third upload, reupload for project2; ensure no duplicates
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id2,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Check dependency_file_upload and resource_instance tables
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 3

    active, deleted, sources = check_active_and_deleted_counts_with_resources(
        db_session=db_session,
        customer_id=customer_id,
        active_id=rows[2].dependency_file_upload_id,
        deleted_id=rows[1].dependency_file_upload_id,
    )
    assert len(active) >= 7
    assert len(deleted) == 0
    assert len(sources) >= 14


@pytest.mark.integration
@pytest.mark.asyncio
def test_upload_same_file_different_projects(
    client,
    customer_id,
    dependency_file_post_call,
    dependency_file_identifier,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    project_id,
    project_id2,
):
    """
    This test verifies that uploading the same dependency file to different projects
    creates separate entries in the database and associates resources correctly with each project.

    The test covers the following scenarios:
    1. Uploading a requirements.txt file to the first project
    2. Verifying that resources are created and associated with the first project
    3. Uploading the same file to a second project
    4. Verifying that new resources are created and associated with the second project
    5. Ensuring that resources for each project are kept separate
    """

    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))
    file.filename = "requirements.txt"

    # Test scenario 1: Upload to first project
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200
    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Test scenario 2: Check resources are created and associated with the first project
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 1

    # there should be seven resources total, all in the first project
    resources = (
        db_session.query(ResourceInstance)
        .filter_by(
            customer_id=customer_id,
        )
        .all()
    )
    assert len(resources) >= 7
    for resource in resources:
        # Verify each resource is associated with exactly one project (the first project)
        projects = resource.projects
        assert len(projects) == 1
        assert projects[0].project_id == project_id

    # Test scenario 3: Upload same file to second project
    file.seek(0)  # Reset file pointer
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id2,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200
    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Test scenarios 4 and 5: Check resources exist and are associated with the second project only
    rows = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(rows) == 2

    # there should still be only six resources - but now they're in both projects
    resources = (
        db_session.query(ResourceInstance)
        .filter_by(
            customer_id=customer_id,
        )
        .all()
    )
    assert len(resources) >= 7
    for resource in resources:
        db_session.refresh(resource)
        # Verify each resource is associated with exactly one project (the second project)
        projects = resource.projects
        assert len(projects) == 2
        # should have both projects
        assert project_id in [p.project_id for p in projects]
        assert project_id2 in [p.project_id for p in projects]


# --------------------------------------- Test Golang --------------------------------------------------


@pytest.fixture
def go_mod():
    return {
        "filename": "go.mod",
        "content": """

        module github.com/alltrue/alltrue

        go 1.22.5

        require (
            github.com/nlpodyssey/gopickle v0.3.0
            github.com/pdevine/tensor v0.0.0-20240510204454-f88f4562727c
            golang.org/x/text v0.3.2
            github.com/apache/arrow/go/arrow v0.0.0-20211112161151-bc219186db40 // indirect
            github.com/bytedance/sonic/loader v0.1.1 // indirect
            github.com/gogo/protobuf v1.3.2 // indirect
        )
        """,
    }


@pytest.fixture
def go_mod_result():
    return [
        ("github-com-nlpodyssey-gopickle", "0.3.0"),
        ("github-com-pdevine-tensor", "0.0.0-20240510204454-f88f4562727c"),
        ("golang-org-x-text", "0.3.2"),
        ("github-com-apache-arrow-go-arrow", "0.0.0-20211112161151-bc219186db40"),
        ("github-com-bytedance-sonic-loader", "0.1.1"),
    ]


@pytest.mark.integration
def test_go_mod_upload_dependencies_api_call(
    client,
    dependency_file_post_call,
    go_mod,
    go_mod_result,
    resource_setup,
    db_session,
    dependency_file_identifier,
    project_id,
    requirements_txt,
    customer_id,
):
    go_language_and_file = LanguageAndFile.GO_GO_MOD
    with get_db_session() as session:
        result = process_dependency_file(
            content_str=go_mod["content"],
            language_and_file=go_language_and_file,
            session=session,
        )
    tuple_result = [
        (dep.library_name, dep.version)
        for dep in result.globally_recognized_dependencies
    ]

    assert Counter(tuple_result) == Counter(go_mod_result)

    # Upload file via api call
    file = io.BytesIO(go_mod["content"].encode("utf-8"))
    requirements_file = requirements_txt["content"]

    # Test invalid file upload first (choosing GO_MOD but passing in a requirements.txt file)
    bad_response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": go_language_and_file.value,
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("go.mod", requirements_file, "text/plain")},
    )
    assert (
        bad_response.status_code == 200
    )  # we don't raise an error anymore, only send to logfire

    # Now upload the correct file
    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": go_language_and_file.value,
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("go.mod", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert response_data == go_mod_result

    # Check that `golang.org/x/text` is cleaned to `text` and has corresponding CVE
    golang_text = response_data[2]
    library_name = golang_text[0]
    version = golang_text[1]

    clean_library_name, clean_version = clean_name_and_version_of_library(
        library_name=library_name, library_version=version, programming_language="Go"
    )
    assert clean_library_name == "text"
    assert clean_version == version

    cpes = list(
        nvdlib.searchCPE_V2(
            keywordSearch=f"{clean_library_name} {clean_version}",
            key=retrieve_nvd_key(),
        )
    )

    cves = [
        nvdlib.searchCVE_V2(
            cpeName=cpe.cpeName,
            key=retrieve_nvd_key(),
            verbose=False,
        )
        for cpe in cpes
    ]
    cves = [list(cve) for cve in cves]
    flat_cves = [cve.id for cve_group in cves for cve in cve_group]

    assert "cpe:2.3:a:golang:text:0.3.2:*:*:*:*:*:*:*" in [cpe.cpeName for cpe in cpes]
    assert "CVE-2020-14040" in flat_cves

    # Check dependency_file_upload table is not empty
    rows = (
        db_session.query(DependencyFileUpload).filter_by(customer_id=customer_id).all()
    )
    dependency_file_upload_id = rows[0].dependency_file_upload_id
    assert len(rows) == 1

    # Check resource_instance table has resources from the dependency file
    rows = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == dependency_file_upload_id,
        )
        .all()
    )
    assert len(rows) == len(go_mod_result)


# ---------------------------------------- Test Delete Dependency File -----------------------------------------------
@pytest.fixture
def dependency_file_delete_call(customer_id) -> str:
    return f"/v1/inventory/customer/{customer_id}/resources/dependency-file"


@pytest.mark.integration
@pytest.mark.asyncio
def test_delete_dependency_file(
    client,
    customer_id,
    dependency_file_post_call,
    dependency_file_delete_call,
    requirements_txt,
    requirements_txt_result,
    resource_setup,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
):
    # Upload a dependency file first which we will then delete
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    response_data = [tuple(item) for item in response.json()]
    assert Counter(response_data) >= Counter(requirements_txt_result)

    # Ensure the dependency file is uploaded
    dependency_files = (
        db_session.query(DependencyFileUpload).filter_by(customer_id=customer_id).all()
    )
    assert len(dependency_files) == 1

    dependency_file = dependency_files[0]
    assert dependency_file.active == True

    dependency_file_upload_id = dependency_file.dependency_file_upload_id

    # Ensure resources are correct
    resource_sources = (
        db_session.query(ResourceSource)
        .filter(
            ResourceSource.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id == dependency_file_upload_id,
        )
        .all()
    )
    assert len(resource_sources) >= 7

    for resource_source in resource_sources:
        resource = get_resource_instance_by_id(
            session=db_session,
            customer_id=customer_id,
            resource_instance_id=resource_source.resource_instance_id,
        )
        assert resource.active.lower() == "active"

    # Now we delete the dependency file
    delete_response = client.delete(
        f"{dependency_file_delete_call}?project_id={project_id}&dependency_file_identifier={dependency_file_identifier}",
    )
    assert delete_response.status_code == 204

    # Refresh the session to reflect changes made by the API call
    db_session.expire_all()

    dependency_files = (
        db_session.query(DependencyFileUpload).filter_by(customer_id=customer_id).all()
    )
    assert (
        len(dependency_files) == 1
    )  # still one file but now active status is set to False

    dependency_file = dependency_files[0]
    assert dependency_file.active == False

    remaining_sources = (
        db_session.query(ResourceSource)
        .filter(ResourceSource.customer_id == customer_id)
        .all()
    )
    assert len(remaining_sources) == 0

    deleted_resources = (
        db_session.query(ResourceInstance)
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceInstance.active == ResourceActive.DELETED,
            ~ResourceInstance.resource_sources.any(),
        )
        .all()
    )
    assert (
        len(deleted_resources) >= 7
    )  # Same resources as above, but now status is set to deleted since only one project
    for resource in deleted_resources:
        assert resource.active.lower() == "deleted"


@pytest.mark.integration
def test_delete_non_existent_dependency_file(
    client,
    dependency_file_delete_call,
    db_session,
    dependency_file_identifier,
    project_id,
):
    response = client.delete(
        f"{dependency_file_delete_call}?project_id={project_id}"
        f"&dependency_file_identifier={dependency_file_identifier}"
    )
    assert response.status_code != 204


@pytest.mark.integration
@pytest.mark.asyncio
def test_delete_dependency_file_multiple_projects(
    client,
    dependency_file_post_call,
    dependency_file_delete_call,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    dependency_file_identifier,
    project_id,
    project_id2,
    customer_id,
):
    # Upload a dependency file to project 1
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    # Upload the same dependency file to project 2

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id2,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    # There should be 2 dependency files in the table, both active
    dependency_files = (
        db_session.query(DependencyFileUpload)
        .filter_by(customer_id=customer_id)
        .order_by(DependencyFileUpload.upload_time.asc())
        .all()
    )
    assert len(dependency_files) == 2
    for df in dependency_files:
        assert df.active == True

    # Ensure resources are associated with both projects and marked as ACTIVE
    resources = (
        db_session.query(ResourceInstance).filter_by(customer_id=customer_id).all()
    )

    assert len(resources) >= 7  # Same 7 resources for both projects

    for resource in resources:
        assert resource.active.lower() == "active"
        projects = [p.project_id for p in resource.projects]
        assert project_id in projects
        assert project_id2 in projects

    # Now delete the dependency file from project 1
    delete_response = client.delete(
        f"{dependency_file_delete_call}?project_id={project_id}&dependency_file_identifier={dependency_file_identifier}",
    )
    assert delete_response.status_code == 204

    # Refresh the session to reflect changes made by the API call
    db_session.expire_all()

    # Dependency file for project 1 should be inactive
    dependency_file_project1 = (
        db_session.query(DependencyFileUpload)
        .filter(
            DependencyFileUpload.customer_id == customer_id,
            DependencyFileUpload.project_id == project_id,
            DependencyFileUpload.dependency_file_identifier
            == dependency_file_identifier,
        )
        .first()
    )
    assert dependency_file_project1.active is False

    # Dependency file for project 2 should still be active
    dependency_file_project2 = (
        db_session.query(DependencyFileUpload)
        .filter(
            DependencyFileUpload.customer_id == customer_id,
            DependencyFileUpload.project_id == project_id2,
            DependencyFileUpload.dependency_file_identifier
            == dependency_file_identifier,
        )
        .first()
    )
    assert dependency_file_project2.active is True

    # Resources should still be active since they are associated with project2
    resources = (
        db_session.query(ResourceInstance).filter_by(customer_id=customer_id).all()
    )
    assert len(resources) >= 7

    for resource in resources:
        assert resource.active.lower() == "active"
        projects = [p.project_id for p in resource.projects]
        assert project_id not in projects
        assert project_id2 in projects

    # ResourceSource entries for project 1 should be removed
    rdf_entries_project1 = (
        db_session.query(ResourceSource)
        .filter(
            ResourceSource.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id
            == dependency_file_project1.dependency_file_upload_id,
        )
        .all()
    )
    assert len(rdf_entries_project1) == 0

    # ResourceSource entries for project 2 should still exist
    rdf_entries_project2 = (
        db_session.query(ResourceSource)
        .filter(
            ResourceSource.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id
            == dependency_file_project2.dependency_file_upload_id,
        )
        .all()
    )
    assert len(rdf_entries_project2) >= 7


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, expected_library_and_versions",
    [
        (
            """
from setuptools import find_packages, setup

setup(
    name="alltrue",
    version="0.0.106",
    url="https://github.com/AllTrue-ai/ai-security-python-api.git",
    author="AllTrue.ai INC",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    author_email="ury@alltrue.ai",
    description="Client Library for AllTrue.ai API",
    install_requires=[
        "setuptools==69.5.1",
        "boto3==1.34.120",
        "pydantic~=2.7.1",
        "python-dotenv==1.0.1",
        "requests>=2.28.1",
        "opensearch-py==2.5.0",
        "botocore~=1.34.63",
        "mypy-boto3-s3~=1.34.65",
        "redis~=5.0.3",
        "rq~=2.0",
        "async-timeout~=4.0.3",
        "pyjwt[crypto]~=2.4.0",
        "fastapi~=0.110.0",
    ],
    extras_require={
        "testing": [
            "pre-commit==3.7.1",
            "pytest==8.2.0",
            "pytest-asyncio~=0.23.8",
            "fakeredis~=2.26.1",
        ],
    },
    python_requires=">=3.10",
)
            """,
            [
                # only the libraries that are considered "AI"
                ("boto3", "1.34.120"),
                ("fastapi", "0.110.0"),
            ],
        ),
        # unexpected format works fine
        (
            """
                This is not a real setup.py file
                """,
            [],
        ),
    ],
)
def test_parse_setup_py_content(file_contents, expected_library_and_versions):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=LanguageAndFile.PYTHON_SETUP_PY,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in results.globally_recognized_dependencies
        ]
    for expected_library, expected_version in expected_library_and_versions:
        assert (expected_library, expected_version) in tuple_results


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, expected_library_and_versions",
    [
        (
            """
            adis-protobuf
            boto3
            cryptography

            boto3-stubs
            black
            flake8
            isort
            mypy
            mypy-boto3-kms
            mypy-boto3-s3
            types-cryptography
            types-protobuf
            """,
            [
                ("boto3", None),
            ],
        ),
        # A bad file (comments only)
        (
            """
                # nothing here
                # just comments
                """,
            [],
        ),
    ],
)
def test_parse_requirements_txt(file_contents, expected_library_and_versions):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=LanguageAndFile.PYTHON_REQUIREMENTS_TXT,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in results.globally_recognized_dependencies
        ]

    for expected_library, expected_version in expected_library_and_versions:
        assert (expected_library, expected_version) in tuple_results


@pytest.mark.unit
def test_parse_requirements_against_env(requirements_txt, environment_yml, dockerfile):
    """
    This test simulates the case when a user might manually upload the wrong python dependency file when another one is
    selected. When PYTHON_REQUIREMENTS_TXT is selected and a requirements file is indeed passed, the results will be
    correct. But when an environment.yml or dockerfile are uploaded when a requirements file is selected, the results
    will not be the same since the format of the files is different.

    For example, a requirements file that contains libraries with no versions will be correctly returned but those same
    libraries in an environment.yml or dockerfile will not be returned since the parser will not be able to parse them.
    """
    with get_db_session() as session:
        requirements_results = process_dependency_file(
            content_str=requirements_txt["content"],
            language_and_file=LanguageAndFile.PYTHON_REQUIREMENTS_TXT,
            session=session,
        )
        assert requirements_results
        environment_results = process_dependency_file(
            content_str=environment_yml["content"],
            language_and_file=LanguageAndFile.PYTHON_ENVIRONMENT_YML,
            session=session,
        )
        # Since the format is similar, we can extract the libraries with versions.
        assert environment_results
        # But libraries with no version are missed due to different format: see missing "albumentations"
        assert all(lib != "albumentations" for lib, _ in environment_results)
        docker_results = process_dependency_file(
            content_str=dockerfile["content"],
            language_and_file=LanguageAndFile.PYTHON_REQUIREMENTS_TXT,
            session=session,
        )
        assert docker_results


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, expected_library_and_versions",
    [
        (
            """
[build-system]
requires = ["pdm-backend"]
build-backend = "pdm.backend"

[project]
name = "fastapi"
dynamic = ["version"]
description = "FastAPI framework, high performance, easy to learn, fast to code, ready for production"
readme = "README.md"
requires-python = ">=3.8"
authors = [
    { name = "Sebastián Ramírez", email = "tiangolo@gmail.com" },
]
classifiers = [
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python",
    "Topic :: Internet",
    "Topic :: Software Development :: Libraries :: Application Frameworks",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Software Development :: Libraries",
    "Topic :: Software Development",
    "Typing :: Typed",
    "Development Status :: 4 - Beta",
    "Environment :: Web Environment",
    "Framework :: AsyncIO",
    "Framework :: FastAPI",
    "Framework :: Pydantic",
    "Framework :: Pydantic :: 1",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3 :: Only",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    "Topic :: Internet :: WWW/HTTP",
]
dependencies = [
    "starlette>=0.40.0,<0.42.0",
    "pydantic>=1.7.4,!=1.8,!=1.8.1,!=2.0.0,!=2.0.1,!=2.1.0,<3.0.0",
    "typing-extensions>=4.8.0",
    "boto3>=1.34.120,!=1.8,!=1.8.1,!=2.0.0,!=2.0.1,!=2.1.0,<3.0.0",
]

[project.urls]
Homepage = "https://github.com/fastapi/fastapi"
Documentation = "https://fastapi.tiangolo.com/"
Repository = "https://github.com/fastapi/fastapi"
Issues = "https://github.com/fastapi/fastapi/issues"
Changelog = "https://fastapi.tiangolo.com/release-notes/"

[project.optional-dependencies]

standard = [
    "fastapi-cli[standard] >=0.0.5",
    # For the test client
    "httpx >=0.23.0",
    # For templates
    "jinja2 >=2.11.2",
    # For forms and file uploads
    "python-multipart >=0.0.7",
    # To validate email fields
    "email-validator >=2.0.0",
    # Uvicorn with uvloop
    "uvicorn[standard] >=0.12.0",
    # TODO: this should be part of some pydantic optional extra dependencies
    # # Settings management
    # "pydantic-settings >=2.0.0",
    # # Extra Pydantic data types
    # "pydantic-extra-types >=2.0.0",
]

all = [
    "fastapi-cli[standard] >=0.0.5",
    # # For the test client
    "httpx >=0.23.0",
    # For templates
    "jinja2 >=2.11.2",
    # For forms and file uploads
    "python-multipart >=0.0.7",
    # For Starlette's SessionMiddleware, not commonly used with FastAPI
    "itsdangerous >=1.1.0",
    # For Starlette's schema generation, would not be used with FastAPI
    "pyyaml >=5.3.1",
    # For UJSONResponse
    "ujson >=4.0.1,!=4.0.2,!=4.1.0,!=4.2.0,!=4.3.0,!=5.0.0,!=5.1.0",
    # For ORJSONResponse
    "orjson >=3.2.1",
    # To validate email fields
    "email-validator >=2.0.0",
    # Uvicorn with uvloop
    "uvicorn[standard] >=0.12.0",
    # Settings management
    "pydantic-settings >=2.0.0",
    # Extra Pydantic data types
    "pydantic-extra-types >=2.0.0",
]

[project.scripts]
fastapi = "fastapi.cli:main"

[tool.pdm]
version = { source = "file", path = "fastapi/__init__.py" }
distribution = true

[tool.pdm.build]
source-includes = [
    "tests/",
    "docs_src/",
    "requirements*.txt",
    "scripts/",
    # For a test
    "docs/en/docs/img/favicon.png",
    ]

[tool.tiangolo._internal-slim-build.packages.fastapi-slim.project]
name = "fastapi-slim"

[tool.mypy]
strict = true

[[tool.mypy.overrides]]
module = "fastapi.concurrency"
warn_unused_ignores = false
ignore_missing_imports = true

[[tool.mypy.overrides]]
module = "fastapi.tests.*"
ignore_missing_imports = true
check_untyped_defs = true

[[tool.mypy.overrides]]
module = "docs_src.*"
disallow_incomplete_defs = false
disallow_untyped_defs = false
disallow_untyped_calls = false

[tool.pytest.ini_options]
addopts = [
  "--strict-config",
  "--strict-markers",
  "--ignore=docs_src",
]
xfail_strict = true
junit_family = "xunit2"
filterwarnings = [
    "error",
    'ignore:starlette.middleware.wsgi is deprecated and will be removed in a future release\..*:DeprecationWarning:starlette',
    # For passlib
    "ignore:'crypt' is deprecated and slated for removal in Python 3.13:DeprecationWarning",
    # see https://trio.readthedocs.io/en/stable/history.html#trio-0-22-0-2022-09-28
    "ignore:You seem to already have a custom.*:RuntimeWarning:trio",
    # TODO: remove after upgrading SQLAlchemy to a version that includes the following changes
    # https://github.com/sqlalchemy/sqlalchemy/commit/59521abcc0676e936b31a523bd968fc157fef0c2
    'ignore:datetime\.datetime\.utcfromtimestamp\(\) is deprecated and scheduled for removal in a future version\..*:DeprecationWarning:sqlalchemy',
    # Trio 24.1.0 raises a warning from attrs
    # Ref: https://github.com/python-trio/trio/pull/3054
    # Remove once there's a new version of Trio
    'ignore:The `hash` argument is deprecated*:DeprecationWarning:trio',
]

[tool.coverage.run]
parallel = true
data_file = "coverage/.coverage"
source = [
    "docs_src",
    "tests",
    "fastapi"
]
context = '${CONTEXT}'
dynamic_context = "test_function"
omit = [
    "docs_src/response_model/tutorial003_04.py",
    "docs_src/response_model/tutorial003_04_py310.py",
]

[tool.coverage.report]
show_missing = true
sort = "-Cover"

[tool.coverage.html]
show_contexts = true

[tool.ruff.lint]
select = [
    "E",  # pycodestyle errors
    "W",  # pycodestyle warnings
    "F",  # pyflakes
    "I",  # isort
    "B",  # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
]
ignore = [
    "E501",  # line too long, handled by black
    "B008",  # do not perform function calls in argument defaults
    "C901",  # too complex
    "W191",  # indentation contains tabs
]

[tool.ruff.lint.per-file-ignores]
"__init__.py" = ["F401"]
"docs_src/dependencies/tutorial007.py" = ["F821"]
"docs_src/dependencies/tutorial008.py" = ["F821"]
"docs_src/dependencies/tutorial009.py" = ["F821"]
"docs_src/dependencies/tutorial010.py" = ["F821"]
"docs_src/custom_response/tutorial007.py" = ["B007"]
"docs_src/dataclasses/tutorial003.py" = ["I001"]
"docs_src/path_operation_advanced_configuration/tutorial007.py" = ["B904"]
"docs_src/path_operation_advanced_configuration/tutorial007_pv1.py" = ["B904"]
"docs_src/custom_request_and_route/tutorial002.py" = ["B904"]
"docs_src/dependencies/tutorial008_an.py" = ["F821"]
"docs_src/dependencies/tutorial008_an_py39.py" = ["F821"]
"docs_src/query_params_str_validations/tutorial012_an.py" = ["B006"]
"docs_src/query_params_str_validations/tutorial012_an_py39.py" = ["B006"]
"docs_src/query_params_str_validations/tutorial013_an.py" = ["B006"]
"docs_src/query_params_str_validations/tutorial013_an_py39.py" = ["B006"]
"docs_src/security/tutorial004.py" = ["B904"]
"docs_src/security/tutorial004_an.py" = ["B904"]
"docs_src/security/tutorial004_an_py310.py" = ["B904"]
"docs_src/security/tutorial004_an_py39.py" = ["B904"]
"docs_src/security/tutorial004_py310.py" = ["B904"]
"docs_src/security/tutorial005.py" = ["B904"]
"docs_src/security/tutorial005_an.py" = ["B904"]
"docs_src/security/tutorial005_an_py310.py" = ["B904"]
"docs_src/security/tutorial005_an_py39.py" = ["B904"]
"docs_src/security/tutorial005_py310.py" = ["B904"]
"docs_src/security/tutorial005_py39.py" = ["B904"]
"docs_src/dependencies/tutorial008b.py" = ["B904"]
"docs_src/dependencies/tutorial008b_an.py" = ["B904"]
"docs_src/dependencies/tutorial008b_an_py39.py" = ["B904"]


[tool.ruff.lint.isort]
known-third-party = ["fastapi", "pydantic", "starlette"]

[tool.ruff.lint.pyupgrade]
# Preserve types, even if a file imports `from __future__ import annotations`.
keep-runtime-typing = true

[tool.inline-snapshot]
# default-flags=["fix"]
# default-flags=["create"]
            """,
            [
                # only the libraries that are considered "AI"
                ("boto3", "1.34.120"),
            ],
        ),
        # unexpected format works fine
        (
            """
            This is not a real pyproject
            """,
            [],
        ),
        (
            """
            [tool.poetry]
            name = "chat-with-docs"
            version = "0.0.5"
            description = "Accurate answers and instant citations for your documents"
            authors = ["tamir-alltrue-ai <tamir@alltrue.ai>"]
            readme = "README.md"
            packages = [{include = "app"}]
            [tool.poetry.dependencies]
            python = "^3.10"
            streamlit = "^1.24.0"
            langchain = "^0.2.1"
            cohere = "^3.2.1"
            faiss-cpu = "^1.7.3"
            openai = "1.51.2"
            docx2txt = "^0.8"
            pillow = "^9.4.0"
            tenacity = "^8.2.0"
            tiktoken = "^0.7.0"
            pycryptodome = "^3.18.0"
            pymupdf = "^1.22.5"
            transformers = "^4.33.1"
            python-dotenv = "^0.21.1"
            httpx = {extras = ["http2"], version = "^0.27.2"}
            langchain-openai = "^0.1.8"
            langchain-community = "^0.2.1"
            ddtrace = "^2.9.2"
            langchain-google-genai = "^1.0.7"
            langchain-anthropic = "^0.1.20"
            google-api-core = "^2.19.1"
            logfire = {extras = ["aiohttp", "httpx", "requests"], version = "^0.53.0"}
            anthropic = "^0.37.1"
            [tool.poetry.group.dev.dependencies]
            pytest = "^7.2.1"
            ipykernel = "^6.23.3"
            ipywidgets = "^8.0.6"
            [tool.poetry.group.lint.dependencies]
            isort = "^5.12.0"
            black = {version = "^23.1a1", allow-prereleases = true}
            flake8 = "^6.0.0"
            [tool.poetry.group.extras.dependencies]
            ipykernel = "^6.25.1"
            [tool.isort]
            profile = "black"
            [build-system]
            requires = ["poetry-core"]
            build-backend = "poetry.core.masonry.api"
            [tool.logfire]
            logfire_console = "False"
            logfire_service_name = "chat-with-docs"
            """,
            (
                [
                    ("Streamlit", "1.24.0"),
                    ("langchain", "0.2.1"),
                    # ("cohere", "3.2.1"),
                    ("faiss-cpu", "1.7.3"),
                    ("openai", "1.51.2"),
                    # ("docx2txt", "0.8"),
                    # ("pillow", "9.4.0"),
                    # ("tenacity", "8.2.0"),
                    # ("tiktoken", "0.7.0"),
                    # ("pycryptodome", "3.18.0"),
                    # ("pymupdf", "1.22.5"),
                    ("transformers", "4.33.1"),
                    # ("python-dotenv", "0.21.1"),
                    # ("httpx", "0.27.2"),
                    ("langchain-openai", "0.1.8"),
                    ("langchain_community", "0.2.1"),
                    # ("ddtrace", "2.9.2"),
                    # ("langchain-google-genai", "1.0.7"),  # TODO: add to registry
                    # ("langchain-anthropic", "0.1.20"),  # TODO: add to registry
                    # ("google-api-core", "2.19.1"),
                    # ("logfire", "0.53.0"),
                    # ("anthropic", "0.37.1"),  # TODO: add to registry
                ]
            ),
        ),
    ],
)
def test_parse_pyproject_contents(file_contents, expected_library_and_versions):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=LanguageAndFile.PYTHON_PYPROJECT_TOML,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in results.globally_recognized_dependencies
        ]
        for expected_library, expected_version in expected_library_and_versions:
            assert (expected_library, expected_version) in tuple_results


@pytest.mark.integration
@pytest.mark.asyncio
def test_reassign_dependency_file(
    client,
    dependency_file_post_call,
    dependency_file_identifier,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    project_id,
    project_id2,
    project_id3,
    customer_id,
):
    """
    Tests the following scenario:


    File is in A
    Resource is in A (project1) and C (project3)
    Reassign file to B
    Resource is in B (project2) and C (project3)
    """
    # Upload a dependency file to project 1
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    # Ensure the dependency file is uploaded
    dependency_files = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload WHERE project_id = :project_id and customer_id = :customer_id"
        ),
        {"project_id": project_id, "customer_id": customer_id},
    ).fetchall()
    assert len(dependency_files) == 1
    dependency_file = dependency_files[0]

    assert dependency_file.project_id == project_id

    # Ensure resources are associated with project 1
    resources = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id
            == dependency_file.dependency_file_upload_id,
        )
        .all()
    )
    assert len(resources)
    num_resources = len(resources)

    for resource in resources:
        # Add resources to project 3: now each resource exists in project 1 and 3
        handle_project_reassignments(
            session=db_session,
            customer_id=customer_id,
            resource_instance_id=resource.resource_instance_id,
            projects_to_assign_to=[project_id3],
        )
        db_session.refresh(resource)
        projects = resource.projects
        assert len(projects) == 2

        expected_projects = {project_id, project_id3}
        assert {p.project_id for p in projects}.issubset(expected_projects)

    # Now reassign the dependency file from project 1 to project 2
    reassign_response = client.put(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "current_project_id": str(project_id),
            "reassign_project_id": str(project_id2),
            "dependency_file_identifier": dependency_file_identifier,
        },
    )
    assert reassign_response.status_code == 200

    # Verify the dependency file is now associated with the new project (project 2)
    reassigned_dependency_files = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload WHERE project_id = :project_id and customer_id = :customer_id"
        ),
        {"project_id": project_id2, "customer_id": customer_id},
    ).fetchall()
    assert len(reassigned_dependency_files) == 1
    reassigned_dependency_file = reassigned_dependency_files[0]

    assert (
        reassigned_dependency_file.dependency_file_upload_id
        == dependency_file.dependency_file_upload_id
    )

    assert reassigned_dependency_file.project_id == project_id2

    # Verify the resources are reassigned to project 2 and project 3
    resources = (
        db_session.query(ResourceInstance)
        .join(
            ResourceSource,
            ResourceSource.resource_instance_id
            == ResourceInstance.resource_instance_id,
        )
        .filter(
            ResourceInstance.customer_id == customer_id,
            ResourceSource.dependency_file_upload_id
            == reassigned_dependency_file.dependency_file_upload_id,
        )
        .all()
    )
    assert (
        len(resources) == num_resources
    )  # Same number of resources as initially uploaded

    for resource in resources:
        # Resource should be in project 2 and 3
        db_session.refresh(resource)
        projects = resource.projects
        assert len(projects) == 2

        expected_projects = {project_id2, project_id3}
        assert {p.project_id for p in projects}.issubset(expected_projects)


@pytest.mark.asyncio
def test_unlink_dependency_file(
    client,
    dependency_file_post_call,
    dependency_file_identifier,
    requirements_txt,
    requirements_txt_result,
    db_session,
    query_params,
    project_id,
    customer_id,
):
    """
    Tests the following scenario:


    File is in A
    Resource is in A (project1) and C (project3)
    Unlink the file
    """
    # Upload a dependency file to project 1
    file = io.BytesIO(requirements_txt["content"].encode("utf-8"))

    response = client.post(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file",
        params={
            "project_id": project_id,
            "language_and_file": query_params["python_requirements"],
            "dependency_file_identifier": dependency_file_identifier,
            "display_name": dependency_file_identifier,
        },
        files={"file": ("requirements.txt", file, "text/plain")},
    )
    assert response.status_code == 200

    # Ensure the dependency file is uploaded
    dependency_files = db_session.execute(
        text(
            "SELECT * FROM dependency_file_upload WHERE project_id = :project_id and customer_id = :customer_id"
        ),
        {"project_id": project_id, "customer_id": customer_id},
    ).fetchall()
    assert len(dependency_files) == 1
    dependency_file = dependency_files[0]

    assert dependency_file.project_id == project_id

    unlink_response = client.put(
        f"/v1/inventory/customer/{customer_id}/resources/dependency-file/bulk-unlink-from-project",
        json=[
            {
                "project_id": str(project_id),
                "dependency_file_identifier": dependency_file_identifier,
            }
        ],
    )
    default_project_id = customer_default_project_id(customer_id=customer_id)
    assert unlink_response.status_code == 200
    dependency_file = (
        db_session.query(DependencyFileUpload)
        .filter_by(
            dependency_file_upload_id=dependency_file.dependency_file_upload_id,
            customer_id=customer_id,
        )
        .one_or_none()
    )
    assert dependency_file.project_id == default_project_id


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, language_and_file, expected_library_and_versions",
    [
        (
            # Maven POM file
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                                 http://maven.apache.org/xsd/maven-4.0.0.xsd">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.alltrue</groupId>
              <artifactId>ai-registry-test</artifactId>
              <version>1.0.0</version>
              <packaging>jar</packaging>

              <dependencies>
                <dependency>
                  <groupId>org.tensorflow</groupId>
                  <artifactId>tensorflow-core-platform</artifactId>
                  <version>0.4.0</version>
                </dependency>
                <dependency>
                  <groupId>org.tribuo</groupId>
                  <artifactId>tribuo-classification-core</artifactId>
                  <version>4.2.1</version>
                </dependency>
                <dependency>
                  <groupId>org.deeplearning4j</groupId>
                  <artifactId>deeplearning4j-core</artifactId>
                  <version>1.0.0-M2.1</version>
                </dependency>
                <dependency>
                  <groupId>ai.h2o</groupId>
                  <artifactId>h2o-core</artifactId>
                  <version>3.38.0.2</version>
                </dependency>
                <dependency>
                  <groupId>com.github.haifengl</groupId>
                  <artifactId>smile-core</artifactId>
                  <version>2.6.0</version>
                </dependency>

                <dependency>
                  <groupId>org.mlflow</groupId>
                  <artifactId>mlflow-client</artifactId>
                  <version>1.30.0</version>
                </dependency>
                <dependency>
                  <groupId>ai.konduit</groupId>
                  <artifactId>konduit-serving</artifactId>
                  <version>0.3.4</version>
                </dependency>
                <dependency>
                  <groupId>io.jpmml</groupId>
                  <artifactId>pmml-evaluator</artifactId>
                  <version>1.5.14</version>
                </dependency>
                <dependency>
                  <groupId>com.cortex</groupId>
                  <artifactId>cortex-core</artifactId>
                  <version>2.3.1</version>
                </dependency>
                <dependency>
                  <groupId>com.unknown</groupId>
                  <artifactId>phantom-ai</artifactId>
                  <version>0.1.0</version>
                </dependency>
              </dependencies>
            </project>
            """,
            LanguageAndFile.JAVA_POM_XML,
            [
                ("org.tensorflow:tensorflow-core-platform", "0.4.0"),
                ("org.tribuo:tribuo-classification-core", "4.2.1"),
                ("org.deeplearning4j:deeplearning4j-core", "1.0.0-M2.1"),
                ("ai.h2o:h2o-core", "3.38.0.2"),
                ("com.github.haifengl:smile-core", "2.6.0"),
            ],
        ),
        (
            # Gradle file
            """
            plugins {
                id 'java'
            }

            group = 'com.alltrue'
            version = '1.0.0'

            repositories {
                mavenCentral()
            }

            dependencies {
                implementation 'org.tensorflow:tensorflow-core-platform:0.4.0'
                implementation 'org.tribuo:tribuo-classification-core:4.2.1'
                implementation 'org.deeplearning4j:deeplearning4j-core:1.0.0-M2.1'
                implementation 'ai.h2o:h2o-core:3.38.0.2'
                implementation 'com.github.haifengl:smile-core:2.6.0'
                compile "com.microsoft.onnxruntime:onnxruntime:${version}"
                api "org.encog:encog-core:1.2.3"
                testImplementation('com.github.neuroph:neuroph-core:1.2.3')
                testRuntimeOnly("edu.stanford.nlp:stanford-corenlp")

                implementation 'org.mlflow:mlflow-client:1.30.0'
                implementation 'ai.konduit:konduit-serving:0.3.4'
                implementation 'io.jpmml:pmml-evaluator:1.5.14'
                implementation 'com.cortex:cortex-core:2.3.1'
                implementation 'com.unknown:phantom-ai:0.1.0'
            }
            """,
            LanguageAndFile.JAVA_BUILD_GRADLE,
            [
                ("org.tensorflow:tensorflow-core-platform", "0.4.0"),
                ("org.tribuo:tribuo-classification-core", "4.2.1"),
                ("org.deeplearning4j:deeplearning4j-core", "1.0.0-M2.1"),
                ("ai.h2o:h2o-core", "3.38.0.2"),
                ("com.github.haifengl:smile-core", "2.6.0"),
                ("com.microsoft.onnxruntime:onnxruntime", None),
                ("org.encog:encog-core", "1.2.3"),
                ("com.github.neuroph:neuroph-core", "1.2.3"),
                ("edu.stanford.nlp:stanford-corenlp", None),
            ],
        ),
    ],
)
def test_parse_java_dependency_file(
    file_contents, language_and_file, expected_library_and_versions
):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=language_and_file,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in results.globally_recognized_dependencies
        ]
        for expected in expected_library_and_versions:
            assert expected in tuple_results


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, language_and_file, expected_library_and_versions",
    [
        (
            # .csproj format
            """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net6.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Microsoft.ML" Version="1.7.1" />
                <PackageReference Include="TorchSharp" Version="0.95.5" />
                <PackageReference Include="SciSharp.TensorFlow.Redist" Version="0.30.0" />
                <PackageReference Include="Keras.NET" Version="3.0.0" />
                <PackageReference Include="Microsoft.Azure.CognitiveServices.Vision.ComputerVision" Version="7.0.1" />
                <PackageReference Include="NumSharp" Version="0.30.0" />
                <PackageReference Include="Numpy" Version="0.13.0" />
              </ItemGroup>
            </Project>
            """,
            LanguageAndFile.CSHARP_CSPROJ,
            [
                ("Microsoft.ML", "1.7.1"),
                ("TorchSharp", "0.95.5"),
                ("SciSharp.TensorFlow.Redist", "0.30.0"),
                ("Keras.NET", "3.0.0"),
                ("Microsoft.Azure.CognitiveServices.Vision.ComputerVision", "7.0.1"),
                ("NumSharp", "0.30.0"),
                ("Numpy", "0.13.0"),
            ],
        ),
        (
            """
            <packages>
              <package id="Microsoft.ML" version="1.7.1" />
              <package id="TorchSharp" version="0.95.5" />
              <package id="SciSharp.TensorFlow.Redist" version="0.30.0" />
              <package id="Keras.NET" version="3.0.0" />
              <package id="Microsoft.Azure.CognitiveServices.Vision.ComputerVision" version="7.0.1" />
              <package id="NumSharp" version="0.30.0" />
              <package id="Numpy" version="0.13.0" />
            </packages>
            """,
            LanguageAndFile.CSHARP_PACKAGES_CONFIG,
            [
                ("Microsoft.ML", "1.7.1"),
                ("TorchSharp", "0.95.5"),
                ("SciSharp.TensorFlow.Redist", "0.30.0"),
                ("Keras.NET", "3.0.0"),
                ("Microsoft.Azure.CognitiveServices.Vision.ComputerVision", "7.0.1"),
                ("NumSharp", "0.30.0"),
                ("Numpy", "0.13.0"),
            ],
        ),
    ],
)
def test_parse_csharp_dependency_file(
    file_contents, language_and_file, expected_library_and_versions
):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=language_and_file,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in results.globally_recognized_dependencies
        ]
        for expected in expected_library_and_versions:
            assert expected in tuple_results


@pytest.mark.unit
@pytest.mark.parametrize(
    "file_contents, language_and_file, expected_library_and_versions",
    [
        (
            """
            {
              "name": "ai-app",
              "private": true,
              "dependencies": {
                "@anthropic-ai/bedrock-sdk": "^0.22.2",
                "@google/genai": "^1.0.0",
                "@google-cloud/aiplatform": "^4.2.0",
                "groq-sdk": "^0.26.0",
                "openai": "^5.3.0",
                "@huggingface/inference": "^3.0.0",
                "@account-ai-shared/fetch": "^2.11.0"
              },
              "devDependencies": {
                "@tensorflow/tfjs": "^4.10.0",
                "eslint": "8.47.0",
                "mocha": "^10.7.3",
                "webpack": "^5.91.0",
                "nyc": "^17.1.0"
              },
              "peerDependencies": {
                "@account-ai-shared/gateway": "^2.1.0",
                "@anthropic-ai/sdk": "^0.54.0",
                "express": "4.21.2"
              }
            }
            """,
            LanguageAndFile.JAVASCRIPT_PACKAGE_JSON,
            [
                ("@anthropic-ai/bedrock-sdk", "0.22.2"),
                ("@google/genai", "1.0.0"),
                ("@google-cloud/aiplatform", "4.2.0"),
                ("groq-sdk", "0.26.0"),
                ("openai", "5.3.0"),
                ("@huggingface/inference", "3.0.0"),
                ("@account-ai-shared/fetch", "2.11.0"),
                ("@tensorflow/tfjs", "4.10.0"),
                ("@account-ai-shared/gateway", "2.1.0"),
                ("@anthropic-ai/sdk", "0.54.0"),
                ("express", "4.21.2"),
            ],
        ),
    ],
)
def test_parse_javascript_package_json(
    file_contents, language_and_file, expected_library_and_versions
):
    with get_db_session() as session:
        results = process_dependency_file(
            content_str=file_contents,
            language_and_file=language_and_file,
            session=session,
        )
        tuple_results = [
            (dep.library_name, dep.version)
            for dep in (
                results.globally_recognized_dependencies
                + results.newly_encountered_dependencies
            )
        ]

        for expected in expected_library_and_versions:
            assert expected in tuple_results


if __name__ == "__main__":
    pytest.main()
