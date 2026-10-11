from django.core.management.base import BaseCommand
from vulnerabilities.models import VulnerabilitySeverity, AdvisorySeverity

class Command(BaseCommand):
    help = "Populate scoring_elements_data for VulnerabilitySeverity and AdvisorySeverity"

    def handle(self, *args, **options):
        self.stdout.write("Starting population of VulnerabilitySeverity...")
        qs = VulnerabilitySeverity.objects.filter(scoring_elements__isnull=False)
        count = qs.count()
        self.stdout.write(f"Found {count} VulnerabilitySeverity records to process.")
        
        for i, severity in enumerate(qs.iterator(chunk_size=1000), start=1):
            severity.save()
            if i % 1000 == 0:
                self.stdout.write(f"Processed {i}/{count} VulnerabilitySeverity records...")
        
        self.stdout.write("Starting population of AdvisorySeverity...")
        qs = AdvisorySeverity.objects.filter(scoring_elements__isnull=False)
        count = qs.count()
        self.stdout.write(f"Found {count} AdvisorySeverity records to process.")
        
        for i, severity in enumerate(qs.iterator(chunk_size=1000), start=1):
            severity.save()
            if i % 1000 == 0:
                self.stdout.write(f"Processed {i}/{count} AdvisorySeverity records...")
                
        self.stdout.write("Population completed.")
