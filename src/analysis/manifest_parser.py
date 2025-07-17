import xml.etree.ElementTree as ET
import os
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class AndroidManifestParser:
    """Parser for Android manifest files to extract deeplink-related information"""
    
    def __init__(self):
        self.namespace = "{http://schemas.android.com/apk/res/android}"
    
    def find_manifest_file(self, repo_manager) -> Optional[str]:
        """Find AndroidManifest.xml file in the repository"""
        file_paths = repo_manager.get_file_paths()
        
        for file_path in file_paths:
            if file_path.endswith("AndroidManifest.xml"):
                logger.debug(f"Found AndroidManifest.xml at: {file_path}")
                return file_path
        
        logger.debug("No AndroidManifest.xml found in repository")
        return None
    
    def parse_manifest(self, manifest_path: str) -> Optional[ET.Element]:
        """Parse the AndroidManifest.xml file"""
        try:
            tree = ET.parse(manifest_path)
            return tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing AndroidManifest.xml: {e}")
            return None
        except FileNotFoundError:
            logger.error(f"AndroidManifest.xml not found at: {manifest_path}")
            return None
    
    def extract_deeplink_activities(self, manifest_path: str) -> Dict[str, List[Dict]]:
        """
        Extract activities that handle deeplinks from AndroidManifest.xml
        
        Returns:
            Dict mapping activity class names to their intent filters
        """
        root = self.parse_manifest(manifest_path)
        if root is None:
            return {}
        
        deeplink_activities = {}
        
        # Find application element
        application = root.find("application")
        if application is None:
            logger.debug("No application element found in manifest")
            return {}
        
        # Find all activities
        for activity in application.findall("activity"):
            activity_name = activity.get(f"{self.namespace}name")
            if not activity_name:
                continue
            
            # Check if activity has intent filters with VIEW action
            intent_filters = []
            for intent_filter in activity.findall("intent-filter"):
                filter_info = self._parse_intent_filter(intent_filter)
                if filter_info and self._is_deeplink_filter(filter_info):
                    intent_filters.append(filter_info)
            
            if intent_filters:
                deeplink_activities[activity_name] = intent_filters
                logger.debug(f"Found deeplink activity: {activity_name} with {len(intent_filters)} intent filters")
        
        return deeplink_activities
    
    def _parse_intent_filter(self, intent_filter: ET.Element) -> Dict:
        """Parse an intent-filter element"""
        filter_info = {
            "actions": [],
            "categories": [],
            "data": []
        }
        
        # Parse actions
        for action in intent_filter.findall("action"):
            action_name = action.get(f"{self.namespace}name")
            if action_name:
                filter_info["actions"].append(action_name)
        
        # Parse categories
        for category in intent_filter.findall("category"):
            category_name = category.get(f"{self.namespace}name")
            if category_name:
                filter_info["categories"].append(category_name)
        
        # Parse data elements
        for data in intent_filter.findall("data"):
            data_info = {}
            for attr in ["scheme", "host", "port", "path", "pathPattern", "pathPrefix", "mimeType"]:
                value = data.get(f"{self.namespace}{attr}")
                if value:
                    data_info[attr] = value
            if data_info:
                filter_info["data"].append(data_info)
        
        return filter_info
    
    def _is_deeplink_filter(self, filter_info: Dict) -> bool:
        """Check if an intent filter represents a deeplink"""
        # Must have VIEW action
        if "android.intent.action.VIEW" not in filter_info["actions"]:
            return False
        
        # Must have BROWSABLE category for web deeplinks
        if "android.intent.category.BROWSABLE" in filter_info["categories"]:
            return True
        
        # Or must have custom scheme/host data
        for data in filter_info["data"]:
            if "scheme" in data or "host" in data:
                return True
        
        return False
    
    def get_exported_components(self, manifest_path: str) -> List[Dict]:
        """Get all exported components that might handle deeplinks"""
        root = self.parse_manifest(manifest_path)
        if root is None:
            return []
        
        exported_components = []
        application = root.find("application")
        if application is None:
            return []
        
        # Check activities, services, and receivers
        for component_type in ["activity", "service", "receiver"]:
            for component in application.findall(component_type):
                component_name = component.get(f"{self.namespace}name")
                exported = component.get(f"{self.namespace}exported")
                
                # Component is exported if explicitly set to true or has intent filters
                is_exported = (exported == "true" or 
                             len(component.findall("intent-filter")) > 0)
                
                if is_exported and component_name:
                    exported_components.append({
                        "type": component_type,
                        "name": component_name,
                        "explicitly_exported": exported == "true"
                    })
        
        return exported_components
    
    def extract_schemes_and_hosts(self, manifest_path: str) -> Dict[str, List[str]]:
        """Extract all custom schemes and hosts used in deeplinks"""
        deeplink_activities = self.extract_deeplink_activities(manifest_path)
        
        schemes = set()
        hosts = set()
        
        for activity, filters in deeplink_activities.items():
            for filter_info in filters:
                for data in filter_info["data"]:
                    if "scheme" in data:
                        schemes.add(data["scheme"])
                    if "host" in data:
                        hosts.add(data["host"])
        
        return {
            "schemes": list(schemes),
            "hosts": list(hosts)
        }
    
    def map_activity_to_files(self, activity_class_name: str, repo_manager) -> List[str]:
        """
        Map an activity class name to its corresponding source files
        
        Args:
            activity_class_name: Full class name like "com.example.MainActivity" or ".MainActivity"
            repo_manager: Repository manager instance
            
        Returns:
            List of file paths that might contain the activity implementation
        """
        # Handle relative class names (starting with .)
        if activity_class_name.startswith("."):
            # We'd need the package name from manifest, for now just use the class name
            simple_name = activity_class_name[1:]  # Remove leading dot
        else:
            # Extract simple class name from full package name
            simple_name = activity_class_name.split(".")[-1]
        
        # Handle inner classes (MainActivity$InnerActivity -> MainActivity)
        base_class = simple_name.split("$")[0]
        
        # Generate possible filenames
        candidates = [
            f"{base_class}.java",
            f"{base_class}.kt",
            f"{base_class}.scala"
        ]
        
        # Search in all file paths
        file_paths = repo_manager.get_file_paths()
        matching_files = []
        
        for file_path in file_paths:
            filename = os.path.basename(file_path)
            if filename in candidates:
                matching_files.append(file_path)
                logger.debug(f"Mapped activity {activity_class_name} to file: {file_path}")
        
        return matching_files
    
    def get_deeplink_analysis_summary(self, manifest_path: str) -> Dict:
        """Get a comprehensive summary for deeplink analysis"""
        deeplink_activities = self.extract_deeplink_activities(manifest_path)
        schemes_hosts = self.extract_schemes_and_hosts(manifest_path)
        exported_components = self.get_exported_components(manifest_path)
        
        return {
            "deeplink_activities": deeplink_activities,
            "total_deeplink_activities": len(deeplink_activities),
            "schemes": schemes_hosts["schemes"],
            "hosts": schemes_hosts["hosts"],
            "exported_components": exported_components,
            "has_deeplinks": len(deeplink_activities) > 0
        }
