import argparse
import sys
import re
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

from custom_modules.netbox_connector import NetboxDevice
from custom_modules.gitlab_connector import GitLabConnector
from custom_modules.log import logger
from custom_modules.errors import Error


@dataclass
class AuditConfig:
    """Конфигурация для аудита"""
    netbox_object_path: str
    netbox_filters: Dict[str, str]
    repo_name_field: str
    gitlab_group_path: str
    gitlab_file_path: str
    search_pattern: str
    ignore_case: bool
    name: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def from_file(cls, config_path: Path) -> 'AuditConfig':
        """Загружает конфигурацию из YAML файла"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            # Проверяем наличие обязательных ключей
            required_sections = ['netbox', 'gitlab', 'search']
            missing_sections = [section for section in required_sections if section not in data]
            if missing_sections:
                raise ValueError(f"Missing required sections in config: {missing_sections}")

            return cls(
                # Опциональные поля с дефолтными значениями
                name=data.get('name', f"Audit from {config_path.stem}"),
                description=data.get('description', "No description provided"),
                # Обязательные поля
                netbox_object_path=data['netbox']['object_path'],
                netbox_filters=data['netbox']['filters'],
                repo_name_field=data['netbox'].get('repo_name_field', 'name'),
                gitlab_group_path=data['gitlab']['group_path'],
                gitlab_file_path=data['gitlab']['file_path'],
                search_pattern=data['search']['pattern'],
                ignore_case=data['search'].get('ignore_case', False)
            )
        except Exception as e:
            raise ValueError(f"Failed to load config from {config_path}: {e}")


class UniversalAuditor:
    """Универсальный аудитор для поиска паттернов в конфигурациях"""

    def __init__(self, config: AuditConfig):
        self.config = config
        self.netbox_objects: List[Any] = []
        self.compiled_pattern = None

    def initialize_connections(self) -> bool:
        """Инициализирует соединения с Netbox и GitLab"""
        try:
            logger.info("Connecting to Netbox...")
            NetboxDevice.create_connection()

            logger.info("Connecting to GitLab...")
            GitLabConnector.create_connection()

            logger.info("Connections established successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to establish connections: {e}")
            return False

    def fetch_netbox_objects(self) -> bool:
        """Получает объекты из Netbox согласно конфигурации"""
        try:
            logger.info(f"Fetching objects: {self.config.netbox_object_path} with filters {self.config.netbox_filters}")

            self.netbox_objects = NetboxDevice.get_netbox_objects(
                self.config.netbox_object_path, 
                action='filter', 
                **self.config.netbox_filters
            )

            if not self.netbox_objects:
                logger.warning("No objects found in Netbox matching the criteria")
                return False

            logger.info(f"Found {len(self.netbox_objects)} objects in Netbox")
            return True
        except Exception as e:
            logger.error(f"Failed to fetch objects from Netbox: {e}")
            return False

    def compile_search_pattern(self) -> bool:
        """Компилирует регулярное выражение для поиска"""
        try:
            flags = re.IGNORECASE if self.config.ignore_case else 0
            # Pattern length check to prevent ReDoS
            if len(self.config.search_pattern) > 100:
                raise ValueError("Pattern too complex")
            self.compiled_pattern = re.compile(self.config.search_pattern, flags=flags)
            logger.info(f"Compiled search pattern: '{self.config.search_pattern}'")
            return True
        except re.error as e:
            logger.error(f"Invalid regular expression pattern: {e}")
            return False

    def search_in_configs(self) -> List[str]:
        """
        Ищет паттерн в проектах GitLab.
        Возвращает список имен устройств, где найден паттерн.
        """
        matching_objects = []

        logger.info("Starting analysis of files from GitLab projects...")

        for obj in self.netbox_objects:
            try:
                repo_name = getattr(obj, self.config.repo_name_field)
            except AttributeError:
                logger.warning(f"Object {obj} missing attribute '{self.config.repo_name_field}'. Skipping.")
                continue

            logger.debug(f"Processing: {repo_name}")

            try:
                # ФОРМИРУЕМ ПОЛНЫЙ ПУТЬ К ПРОЕКТУ
                full_project_path = f"{self.config.gitlab_group_path}/{repo_name}"

                # ПОЛУЧАЕМ ПРОЕКТ ДЛЯ ТЕКУЩЕГО УСТРОЙСТВА
                device_project = GitLabConnector.get_project(full_project_path)

                # Получаем содержимое файла из этого конкретного проекта
                content = GitLabConnector.get_file_content(
                    device_project,
                    file_path=self.config.gitlab_file_path
                )

            except Error as e:
                # Ловим ошибку 404, если проекта для устройства нет
                if '404' in str(e):
                    logger.warning(f"Project for '{repo_name}' not found at path '{full_project_path}'. Skipping.")
                    continue
                else:
                    logger.error(f"An error occurred for device '{repo_name}': {e}")
                    continue

            if content and self.compiled_pattern.search(content):
                logger.info(f"Pattern match found in '{repo_name}'")
                matching_objects.append(repo_name)

        return matching_objects

    def run_audit(self) -> List[str]:
        """Выполняет полный цикл аудита"""
        logger.info(f"Starting audit: {self.config.name}")

        # Пошаговое выполнение с проверкой результата каждого шага
        if not self.initialize_connections():
            return []

        if not self.fetch_netbox_objects():
            return []

        if not self.compile_search_pattern():
            return []

        return self.search_in_configs()


def list_available_configs() -> None:
    """Выводит список доступных конфигурационных файлов"""
    config_dir = Path('configs')
    if not config_dir.exists():
        print("No config directory found. Please create 'configs/' directory with YAML files.")
        return

    config_files = list(config_dir.glob('*.yaml')) + list(config_dir.glob('*.yml'))

    if not config_files:
        print("No configuration files found in configs/ directory.")
        return

    print("Available configurations:")
    for config_file in sorted(config_files):
        print(f"  - {config_file.name}")

        # Пытаемся прочитать описание из файла
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                description = data.get('description', 'No description')
                # Обрезаем длинное описание
                if len(description) > 60:
                    description = description[:60] + "..."
                print(f"    {description}")
        except Exception:
            print("    Unable to read config file")


def load_audit_config(config_name: str) -> AuditConfig:
    """Загружает и валидирует конфигурацию аудита"""
    # Ищем конфиг в папке configs/
    config_path = Path('configs') / config_name

    # Если расширение не указано, пробуем .yaml
    if not config_path.suffix:
        config_path = config_path.with_suffix('.yaml')

    if not config_path.exists():
        # Попробуем также .yml если .yaml не найден
        if config_path.suffix == '.yaml':
            config_path_yml = config_path.with_suffix('.yml')
            if config_path_yml.exists():
                config_path = config_path_yml
            else:
                raise FileNotFoundError(f"Configuration file not found: {config_path} or {config_path_yml}")
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        config = AuditConfig.from_file(config_path)
        logger.info(f"Loaded configuration: {config.name}")
        return config
    except ValueError as e:
        raise ValueError(f"Configuration error: {e}")


def print_audit_report(config: AuditConfig, results: List[str]) -> None:
    """Выводит отчет о результатах аудита"""
    print("\n" + "=" * 50)
    print("UNIVERSAL AUDIT REPORT")
    print("=" * 50)
    print(f"Audit: {config.name}")
    print(f"Description: {config.description}")
    print(f"Search Pattern: {config.search_pattern}")
    print("-" * 50)

    if results:
        print(f"Found {len(results)} matching objects:")
        print()
        for item in sorted(results):
            print(f"  ✓ {item}")
    else:
        print("No matching objects found.")

    print("\n" + "=" * 50 + "\n")


def parse_arguments() -> argparse.Namespace:
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(
        description="Universal tool for auditing network configurations",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'config', 
        nargs='?',
        help="Configuration file name (without path, will be searched in configs/ directory)"
    )
    parser.add_argument(
        '--list-configs', 
        action='store_true',
        help="List available configuration files in configs/ directory"
    )

    return parser.parse_args()


def run_audit_workflow(config_path: str) -> None:
    """Выполняет полный рабочий процесс аудита"""
    # Загружаем конфигурацию
    config = load_audit_config(config_path)

    # Создаем и запускаем аудитор
    auditor = UniversalAuditor(config)
    results = auditor.run_audit()

    # Выводим отчет
    print_audit_report(config, results)


def main() -> None:
    """Главная функция-оркестратор"""
    args = parse_arguments()

    # Обработка опции просмотра конфигураций
    if args.list_configs:
        list_available_configs()
        return

    # Проверяем, что указан путь к конфигурации
    if not args.config:
        print("Error: Please specify a configuration file name or use --list-configs")
        print("Usage: python find_smth_in_gitlab.py <config_name>")
        print("Example: python find_smth_in_gitlab.py find_vlans_101")
        sys.exit(1)

    # Выполняем аудит
    try:
        run_audit_workflow(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during audit: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)