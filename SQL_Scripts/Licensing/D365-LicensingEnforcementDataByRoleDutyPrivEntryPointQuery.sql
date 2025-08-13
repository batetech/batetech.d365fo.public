/*=========================================================================================================
IMPORTANT: This script does NOT use the same exact calculation as Microsoft's PPAC and USG reporting. 
		These results are intended to be used as a tool to help with licensing analysis, but is not the "source of truth" and may give different results than the Microsoft calc,  '
		even though the script does use the base data from the USG licensing tables for the calculations.
=========================================================================================================
PURPOSE:
The PPAC and D365 "User Security Goverance" (USG) reports do not provide a Duty and Privilege level infomation alongside the required license information. 
So when cleaning up security objects (roles, duties, privs) it becomes a very tediuous task. 
This script will show Role, Duty, Priv, Entry Point (aka Entitlement Object), permissions, and required license info, 
and also includes the ability to compare your "expected" licenses for roles to actual required, and see which entry points are causing a role to 
require a higher than expected license. 

REQUIREMENTS: 
* D365 10.0.44 or higher, with the following features enabled: 
	- User security governance
	- (Preview) User security governance license usage summary report
* SQL JIT access to your environment database.  This script will work with "Reader" access. 
* Some features (showing duties and entry point permissions) require you to run the "Rebuild" action from form "System administration > Security > Security governance > Security analysis".
	You can set this up as a recurring batch job to keep the data refreshed (every night, etc.). 

DETAILS FOR HOW TO USE THIS SCRIPT: 
* You can get SQL JIT access to a non-production LCS Tier 2+ or PPAC UDE/USE environment to execute this query via SQL Server Management Studio (SSMS). 
* see "SECTION: SET PARAMETER VALUES:" in the script below for more info about parameters you can use. You can adjust values in this section to impact the query results. 
* When @showRoleLevelLicenseSummary = 1, it will show a summary of required licenses by Role with one row per required license
* When @showLicenseDetails = 1, it will show details for required vs. expected licenses at the Role, Duty, Priv, and Entry point (aka Entitlement Object) levels. 
* If you populate @tblExpectedLicenses roleName and skuName columns, and set @showLicenseDetails = 1, then it will show you all the detailed entry points 
	which cause the required licenses for this Role to be higher the expected license.
	If @tblExpectedLicenses is populated, but no entry points cause additional licenses for this Role, then nothing will show in the Details view for the role. You can leave the @tblExpectedLicenses.skuName blank to see all entry points for the role.
* You can also filter using the @roleName variable (using a SQL "like" pattern with % as wildcard) 
* If you run wide open with no filters set, then it may take a long time to run. 
* Note: the "System Administrator" role does not require any license, and has no "entry points" assigned so will not appear in these results. 
* Any roles which have no "entry points" assigned (i.e. no permissions set) will not appear in these results. 

KNOWN/OPEN ISSUES: 
	* If a Role showed required license groups of: 
		- Finance or SCM
		- Proj ops
		Then it would show as requiring Finance + Proj Ops (since Finance has lower priority than SCM), but would not show the option for SCM + Proj ops. How to handle this? 
	* If a Role showed required license groups of: 
		- Finance or SCM
		- Proj ops OR SCM
		Then it would show as requiring SCM (since one license would cover all), but would not show the option for Finance + Proj Ops combination which would also cover the license requirements. How to handle this? 
*/
if object_id('tempdb..#tmpRoleLicenseCalc') is not null
	drop table #tmpRoleLicenseCalc;
if object_id('tempdb..#tmpLicDetails') is not null
	drop table #tmpLicDetails;
if object_id('tempdb..#tmpRoleLicenseSummary') is not null
	drop table #tmpRoleLicenseSummary;
if object_id('tempdb..#tmpLicUnpivot') is not null
	drop table #tmpLicUnpivot;
if object_id('tempdb..#tblExpectedLicensesInternal') is not null
	drop table #tblExpectedLicensesInternal;
go
set nocount on;
--===========================================
--SECTION: PRINT IMPORTANT MESSAGES
declare @print bit = 1;
if @print = 1
begin
	print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
	print 'IMPORTANT: This script does NOT use the same exact calculation as Microsoft''s PPAC and USG reporting. '
	print '		These results are intended to be used as a tool to help with licensing analysis, but is not the "source of truth" and may give different results than the Microsoft calc,  ';
	print '		even though the script does use the base data from the USG licensing tables for the calculations.'
	print '		Use at your own risk.'
	print '--------------------------------------------------------------------------------------------------------'
end;
select msg = 'See the "Messages" tab for important information. (You can comment out this line in SECTION: PRINT IMPORTANT MESSAGES so it does not appear every time)';
declare @includeRoles int, @includeDuties int, @includePrivs bit, @roleName nvarchar(256) , @dutyName nvarchar(256) , @privName nvarchar(256), @entryPointName nvarchar(256), @userID nvarchar(256), @minSKUPriorityGreaterThanOrEqualTo int
	, @showLicenseDetails bit, @showRoleLevelLicenseDetails bit, @showRoleLevelLicenseSummary bit, @showRoleUserLevelSummary bit, @displayParamValues bit;
declare @tblExpectedLicenses table (roleName nvarchar(256), skuName nvarchar(256), skuPriority int);
--============================================================================
--SECTION: SET PARAMETER VALUES: 
--	Update the parameter values below to filter data. Use % as wildcard.  
--  Remove the "--" prefix to uncomment these variables to use them.
---------------------------------------------------------
--Whether or not to group by role/priv names in output
set @includeRoles = 1; -- 0 = Do not include role and rollup to level that doesn't include roles; 1 = Yes with a separate row per each role; 2 = Yes but in summary mode where all Roles are shown for this priv/entry point combo
set @includeDuties = 1; -- 0 = Do not include duty and rollup to level that doesn't include duty; 1 = Yes with a separate row per each Duty; 2 = Yes but in summary mode where all Duties are shown for this priv/entry point combo
set @includePrivs = 1; -- 0 = Do not include priv and rollup to level that doesn't include privs; 1 = Yes with a spearate row per each priv;
---------------------------------------------------------
--Recommend to start with @showRoleLevelLicenseSummary = 1, and find any rows where coversExpectedLicense = 0 or matchesExpectedLicense = 0.
--	Then run again for thoes specific roles with @showRoleLevelLicenseSummary = 0 and @showLicenseDetails = 1 to see the details for what is causing an unexpected license.
set @showRoleLevelLicenseSummary = 1; --If 1, show a summary of required licenses by Role with one row per required license
--set @showLicenseDetails = 1; --It is strongly recommeneded to use other filters is this is set to 1. If 1 show the details at the entry point level for required licenses, optionally at the Role, duty, and priv level, pivoted by License SKU. This is helpful in troubleshooting expected vs. required licenses at a granual level. 
--set @showRoleUserLevelSummary = 1; --If 1 show the same info as @showRoleLevelLicenseSummary but at the user level also 
--set @showRoleLevelLicenseDetails = 1; --Used mainly for troubleshooting. If 1, show a listing of all groups of distinct required license combinations for each Role. If example, if one entry point is entitled for Finance and SCM, but other is entitled for Finance, SCM, and Project Operations, you would see 2 rows: one for "Finance; SCM;" and one for "Finance; SCM; Project operations;"
set @displayParamValues = 1; --If 1, then show the parameters that were used
---------------------------------------------------------
--Other filters: 
--set @roleName = 'Accounts payable%';  --Use % as wildcard when searching
--set @entryPointName = 'HCMWORKERDIRPARTYPOSTALADDRESSEDIT'; --Filter by entry point. Can be used to show everywhere an entry point it used. 
--set @dutyName = 'Approve purchase order%'; --Filter by duty name
--set @privName = 'Maintain approved purchase requisitions';
--set @userID = 'april'; --filter by D365 user ID
--	Get the priority value from here: select * from LICENSINGALLSKUS sku order by sku.PRIORITY
--set @minSKUPriorityGreaterThanOrEqualTo = 30; --show anything higher than this sku priority. i.e. 30 would mean anything Operations - Activity license or higher
---------------------------------------------------------
--Filter using @tblExpectedLicenses table varible: 
--	Populate the @tblExpectedLicenses table variable below with a list of Role names and the license SKU names that you expect for each.
--	SQL Wildcards (%) are allowed for Role names in this table.
/*
Get skuName to use with @tblExpectedLicenses from this query: 
	select * from LICENSINGALLSKUS sku order by sku.PRIORITY;

SKU Names as of 2025-08-01:
	None
	Human Resources Self Service
	Team Members
	Operations - Activity
	Human Resources
	Project Operations
	Commerce
	Finance
	Supply Chain Management
	Finance Premium
	Supply Chain Management Premium
*/
/**/
--EXAMPLE 1: 
SELECT MSG = 'EXAMPLE 1: show all required licenses for the top 100 roles assigned to users, without any expected licenses listed.';
insert into @tblExpectedLicenses(skuName, roleName)
select top 100 skuName = '', roleName = sr.NAME 
from SECURITYROLE sr 
where exists(select 1 
					from SECURITYUSERROLE ru 
						inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
					where ru.SECURITYROLE = sr.RECID
						and ru.ASSIGNMENTSTATUS = 1 
						and u.ENABLE = 1
						and u.ISMICROSOFTACCOUNT = 0
					)
;
--**/
/***
--EXAMPLE 2: demo of expected vs. required mismatches for OOTB roles. 
select MSG = 'EXAMPLE 2 Note: the expected license skuName values below are just for demo purposes and are NOT what I would actually expect for these roles.'
insert into @tblExpectedLicenses(skuName, roleName)
values 
  ('Finance Premium ', 'Accountant') --expected covers the required license, but doesn't match the lowest required
, ('Team Members', 'Auditor') --expect Team Members, but this role requires Finance OR Finance Premium, so it will show in the results as a mismatch
, ('Finance', 'Accounting manager') --expected = required here
, ('Operations - Activity', 'Collections agent') --we expect Operations - Activity, but this role requires Finance OR Finance Premium so will show in the results.
, ('Finance', 'Chief executive officer') --we expect Finance, but this role requires Operations - Activity so will show in the results as matchesExpectedLicense = 0, and coversExpectedLicense = 1.
;
--**/
/***
--EXAMPLE 3 - complex usage of @tblExpectedLicenses for a list of custom roles with expected licenses assigned for each role to compare to calculated required roles:
--	This is what I'm using for my peronsal licensing analysis for our environment.
--SELECT MSG='EXAMPLE 3: complex usage of @tblExpectedLicenses for a list of custom roles with expected licenses assigned to analysis to compare to required roles';
insert into @tblExpectedLicenses(skuName, roleName)
values 
	  ('Finance', 'CE-AP 1099 Maintenance')
	, ('Finance', 'CE-AP Admin')
	, ('Finance', 'CE-AP Assigner')
	, ('Finance', 'CE-AP Delete Invoice')
	, ('Finance', 'CE-AP Invoice Variance Approver')
	, ('Finance', 'CE-AP Invoicing')
	, ('Finance', 'CE-AP Payments')
	, ('Finance', 'CE-AP PO Invoicing')
	, ('Finance', 'CE-AP Post NOI Invoice')
	, ('Finance', 'CE-AP Vendor Master')
	, ('Finance', 'CE-AR Accountant')
	, ('Finance', 'CE-AR Customer Master')
	, ('Finance', 'CE-AR % Invoice Import')
	, ('Finance', 'CE-AR Free Text Invoice % Approval')
	, ('Finance', 'CE-AR Invoicing')
	, ('Finance', 'CE-Audit Configuration Admin')
	, ('Finance', 'CE-Bank Setup Admin')
	, ('Finance', 'CE-Budgeting')
	, ('Supply Chain Management', 'CE-Buying agent')
	, ('Team Members', 'CE-Daily Purchase Order Lines Report')
	, ('Finance', 'CE-FA Accountant')
	, ('Finance', 'CE-FA Admin')
	, ('Finance', 'CE-GL Accountant')
	, ('Finance', 'CE-GL Admin')
	, ('Finance', 'CE-GL COA Maintenance')
	, ('Finance', 'CE-GL Period Maintenance')
	, ('Supply Chain Management', 'CE-Inventory')
	, ('Project Operations', 'CE-Inventory') -- since this role can create proj item journals
	, ('Supply Chain Management', 'CE-Inventory Admin')
	, ('Project Operations', 'CE-Inventory Admin') -- since this role can create proj item journals
	, ('Supply Chain Management', 'CE-Inventory Replenishment')
	, ('Supply Chain Management', 'CE-Inventory Replenishment Admin')
	, ('None', 'CE-IT Support Admin')
	, ('Finance', 'CE-Legal Entity Admin')
	--, ('Human Resources', 'CE-Maintain worker record') --updating worker addresses currently requires HR as of 2025-08-12
	, ('Supply Chain Management', 'CE-Maintain worker record') 
	, ('Operations - Activity', 'CE-PO Requisitions and Receipts')
	, ('Operations - Activity', 'CE-Process Receipt Corrections')
	, ('Project Operations', 'CE-Projects Accountant')
	, ('Project Operations', 'CE-Projects Admin')
	, ('Project Operations', 'CE-Projects Hour Journals')
	, ('Project Operations', 'CE-Projects-Setups by Group-Equipment')
	, ('Project Operations', 'CE-Projects-Setups by Group-WIP')
	, ('Team Members', 'CE-Receipt Details Report')
	, ('None', 'CE-Security Admin')
	, ('Supply Chain Management', 'CE-Sourcing')
	, ('Supply Chain Management', 'CE-Sourcing Administrator')
	, ('Supply Chain Management', 'CE-Sourcing Administrator Buying Agent')
	, ('Finance', 'CE-TEMP Data Management Admin')
	, ('Finance', 'CE-Treasurer')
	, ('Finance', 'CE-Workflow Admin')
	--, ('Human Resources', 'CE-Workflow Admin') --this includes the ability to update jobs, positions, workers, etc. which requires HR in addition to Finance.
	, ('Team Members', 'CE-SysAdmin Read-Only')
	, ('Team Members', 'System user')
;
--select * from dbo.SECURITYROLE sr order by sr.NAME

--Anything not explicitly inserted above that is inquiry/read-only is expected to be a Team member license.
insert into @tblExpectedLicenses(skuName, roleName)
select skuName = 'Team Members', roleName = r.NAME
from SECURITYROLE r 
where (r.NAME like 'CE-%Inquiry%'
	or r.name like 'CE-%Read-Only%'
	or r.name like 'CE-%Read'
	or r.name like 'CE-%ReadOnly'
	or r.name like 'CE-%' --any other custom roles not listed above, default to "Team Members" license so anything higher will show
	)
	and not exists(select 1 from @tblExpectedLicenses e where r.NAME like e.roleName)
;

--include any other roles with assigned users, default to Team license so anything higher will show
insert into @tblExpectedLicenses(skuName, roleName)
select skuName = 'Team Members', roleName = sr.NAME 
from SECURITYROLE sr 
where exists(select 1 
					from SECURITYUSERROLE ru 
						inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
					where ru.SECURITYROLE = sr.RECID
						and ru.ASSIGNMENTSTATUS = 1 
						and u.ENABLE = 1
						and u.ISMICROSOFTACCOUNT = 0
					)
	and not exists(select 1 from @tblExpectedLicenses e where sr.NAME like e.roleName)
;

--**/

/*****
--EXAMPLE 4: Expected licenses for a user. NOTE: you need to set the "@userID" variable to a valid enabled user for this to work. 
--if @userID is missing, set username to first enabled user with a role assigned
set @userID = isnull(@userID, (select top 1 u.id from USERINFO u inner join SECURITYUSERROLE ru on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION and ru.ASSIGNMENTSTATUS = 1 where u.ENABLE = 1 and u.ISMICROSOFTACCOUNT = 0 order by case when u.ID = 'admin' then 1 else 0 end, u.ID)); 

insert into @tblExpectedLicenses(skuName, roleName)
select skuName = el.ExpectedLicense, roleName = sr.NAME 
from SECURITYROLE sr 
cross apply (
	          select ExpectedLicense = 'Supply Chain Management'
	union all select ExpectedLicense = 'Project Operations'
) el
where exists(select 1 
					from SECURITYUSERROLE ru 
						inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
					where ru.SECURITYROLE = sr.RECID
						and ru.ASSIGNMENTSTATUS = 1 
						and u.ENABLE = 1
						and u.ISMICROSOFTACCOUNT = 0
						and u.ID = @userID
					)
	and not exists(select 1 from @tblExpectedLicenses e where sr.NAME like e.roleName)
;
--**/

--select [@tblExpectedLicenses]='',* from @tblExpectedLicenses;
--end @tblExpectedLicenses

--END SECTION: SET PARAMETER VALUES
--===============================================================================
--===============================================================================
--===============================================================================
-- YOU SHOULD NOT NEED TO CHANGE ANYTHING BELOW THIS LINE: 
if isnull(@showLicenseDetails, 0) <> 1 and isnull(@showRoleLevelLicenseDetails, 0) <> 1 and isnull(@showRoleLevelLicenseSummary, 0) <> 1
begin
	if @print = 1
	begin
		print N'Info: You should set one of the following parameter values to 1: @showLicenseDetails, @showRoleLevelLicenseDetails, @showRoleLevelLicenseSummary.  Since all were 0, we set @showRoleLevelLicenseSummary = 1 to return data.';
	end;
	set @showRoleLevelLicenseSummary = 1;
end;

update el set el.skuPriority = ISNULL(s.[PRIORITY], 0)
from @tblExpectedLicenses el
	LEFT join LICENSINGALLSKUS s on el.skuName = s.SKUNAME
;

if isnull(@roleName, '') <> ''
begin
	--if filtering by @roleName, then remove role names that don't match, since it just adds overhead to leave them
	delete el 
	from @tblExpectedLicenses el 
	where el.roleName not like @roleName
	;
end;

create table #tblExpectedLicensesInternal (roleName nvarchar(256), skuName nvarchar(256), skuPriority int, roleRecID bigint, roleAOTName nvarchar(256));
insert into #tblExpectedLicensesInternal(roleName, skuName, skuPriority, roleRecID, roleAOTName)
select distinct sr.NAME, isnull(el.skuName, ''), isnull(el.skuPriority, 0), sr.RECID, sr.AOTNAME
from @tblExpectedLicenses el 
inner join SECURITYROLE sr on sr.NAME like el.roleName
;

create index ix_tblExpectedLicensesInternal_aotname on #tblExpectedLicensesInternal(roleAOTName);
create index ix_tblExpectedLicensesInternal_roleRecID on #tblExpectedLicensesInternal(roleRecID);


--select * from #tblExpectedLicensesInternal el order by el.roleName;

if (@showRoleLevelLicenseDetails = 1 or @showRoleLevelLicenseSummary = 1) and (@includeDuties = 1 or @includePrivs = 1)
begin
	if isnull(@showLicenseDetails, 0) = 0 and isnull(@dutyName, '') = '' and isnull(@privName, '') = ''
	begin
		if @print = 1
		begin
			print 'Info: @includeDuties and @includePrivs were reset to 0 since only viewing at the Role level to performance improvement';
		end;
		set @includeDuties = 0; --no need for these details if showing at the role level
		set @includePrivs = 0; --no need for these details if showing at the role level
		set @includeRoles = 1; --if one of @showRoleLevel = 1 then we need to set this flag to include Roles in the data. 
	end
	--else
	--begin
	--	select msg = 'TIP: If showing role level info, then setting @includeDuties = 0 and @includePrivs = 0 will allow the query to run faster.'
	--end
	;
end;

if @showLicenseDetails = 1
	AND (exists(select 1 from USERSECGOVRELATEDOBJECTS so where so.MODIFIEDDATETIME < dateadd(day, -3, getdate()))
	or not exists(select 1 from USERSECGOVRELATEDOBJECTS so )
	)
begin
	declare @msg nvarchar(max);
	select @msg = concat('WARNING: USERSECGOVRELATEDOBJECTS table was last built: ',format(isnull(max(so.MODIFIEDDATETIME), '1900-01-01'), 'yyyy-MM-dd HH:mm'),'. For some of this data to come through correctly (for access permissions and duties), you have to "Rebuild" on the "Security analysis" (UserSecGovRelatedObjects) form.')
	from USERSECGOVRELATEDOBJECTS so 
	;
	select [WARNING] = @msg;
	--raiserror (@msg, 16, 1); --don't make this an error, just output so the user is aware. 
end;

if @displayParamValues = 1
begin
	select parameterValues='You can turn off this message by setting @displayParamValues = 0. This lists the values of parameters/filters used when executing the query.'
		, [@includeRoles] = @includeRoles
		, [@includeDuties] = @includeDuties
		, [@includePrivs] = @includePrivs
		, [@roleName] = @roleName
		, [@dutyName] = @dutyName
		, [@privName] = @privName
		, [@entryPointName] = @entryPointName
		, [@userID] = @userID
		, [@minSKUPriorityGreaterThanOrEqualTo] = @minSKUPriorityGreaterThanOrEqualTo
		, [@showLicenseDetails] = @showLicenseDetails
		, [@showRoleLevelLicenseDetails] = @showRoleLevelLicenseDetails
		, [@showRoleLevelLicenseSummary] = @showRoleLevelLicenseSummary
		, [@showRoleUserLevelSummary] = @showRoleUserLevelSummary
		, [ExpectedLicRoleCount based on @tblExpectedLicenses] = (select count(el.roleName) from #tblExpectedLicensesInternal el)
	;
end;

;with ctePrivRoles as(
	select 
		  RoleName = case when @includeRoles = 1 then sr.NAME end
		, RoleAOTName = case when @includeRoles = 1 then sr.AOTNAME end
		, duty = case 
				when @includeDuties = 1
				then isnull(case when @includeDuties = 1 then uso.DutyName end, '')
				when @includeDuties = 2
				then
				(
					select distinct concat(c.DUTYNAME, '; ')
					from UserSecGovRelatedObjects c --this table takes sub roles into account already
					where c.PRIVILEGEIDENTIFIER = case when @includePrivs = 1 then sp.IDENTIFIER end
						and c.ROLEIDENTIFIER = case when @includeRoles = 1 then sr.AOTNAME end
						and c.DUTYIDENTIFIER <> N''
					order by 1
					for xml path('')
				)
				end
		, dutyID = case 
				when @includeDuties = 1
				then isnull(case when @includeDuties = 1 then uso.DutyIdentifier end, '')
				when @includeDuties = 2
				then (
					select distinct concat(c.DUTYIDENTIFIER, '; ')
					from UserSecGovRelatedObjects c --this table takes sub roles into account already
					where c.PRIVILEGEIDENTIFIER = case when @includePrivs = 1 then sp.IDENTIFIER end
						and c.ROLEIDENTIFIER = case when @includeRoles = 1 then sr.AOTNAME end
						and c.DUTYIDENTIFIER <> N''
					order by 1
					for xml path('')
				)
				end
		, PrivName = case when @includePrivs = 1 then sp.NAME end
		, PrivID = case when @includePrivs = 1 then sp.IDENTIFIER end
		
		, SECURABLETYPENAME =  eo.SECURABLETYPENAME
		, EntryPoint_AOTName = isnull(eo.AOTNAME, v.AOTNAME)
		, EntryPoint_AOTChildName = eo.AOTCHILDNAME

		, minPriority = min(v.PRIORITY)
		, minRequiredLicense = (select sku.SKUNAME from LICENSINGALLSKUS sku where sku.PRIORITY = min(v.PRIORITY))
		, expectedMinPriority = (select min(el.skuPriority) from #tblExpectedLicensesInternal el where el.skuPriority is not null and el.roleRecID = case when @includeRoles = 1 then sr.RECID end)
		, expectedMinSKU = (select las.SKUNAME from licensingallskus las where las.PRIORITY = (select min(el.skuPriority) from #tblExpectedLicensesInternal el where el.skuPriority is not null and el.roleRecID = case when @includeRoles = 1 then sr.RECID end))
		, expectedAllSKUs = (select concat(el.skuName, '; ') from #tblExpectedLicensesInternal el where el.roleRecID = case when @includeRoles = 1 then sr.RECID end for xml path(''))
		
		, ACCESSLEVELDesc = case max(v.ACCESSLEVEL) when 1 then 'Read' when 2 then 'Write' else concat('-Unknown-', max(v.ACCESSLEVEL)) end
		--, AnyFin = max(case when v.skuname in ('Finance', 'Finance Premium') and v.ENTITLED = 1 then 1 else 0 end) 
		--, AnySCM = max(case when v.skuname in ('Supply Chain Management', 'Supply Chain Management') and v.ENTITLED = 1 then 1 else 0 end) 
		--, AnyProj = max(case when v.skuname in ('Project Operations') and v.ENTITLED = 1 then 1 else 0 end) 
		
		, [Finance] = max(case when v.skuname = 'Finance' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Supply Chain Management] = max(case when v.skuname = 'Supply Chain Management' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Project Operations] = max(case when v.skuname = 'Project Operations' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Operations - Activity] = max(case when v.skuname = 'Operations - Activity' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Team Members] = max(case when v.skuname = 'Team Members' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Human Resources] = max(case when v.skuname = 'Human Resources' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Human Resources Self Service] = max(case when v.skuname = 'Human Resources Self Service' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Commerce] = max(case when v.skuname = 'Commerce' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Finance Premium] = max(case when v.skuname = 'Finance Premium' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Supply Chain Management Premium] = max(case when v.skuname = 'Supply Chain Management Premium' and v.ENTITLED = 1 then 1 else 0 end) 
		, [None] = max(case when v.skuname = 'None' and v.ENTITLED = 1 then 1 else 0 end) 

		, READACCESS = max(isnull(uso.READACCESS, sec.READACCESS))
		, CORRECTACCESS = max(isnull(uso.CORRECTACCESS, sec.CORRECTACCESS))
		, CREATEACCESS =  max(isnull(uso.CREATEACCESS, sec.CREATEACCESS))
		, UPDATEACCESS =  max(isnull(uso.UPDATEACCESS, sec.UPDATEACCESS))
		, DELETEACCESS =  max(isnull(uso.DELETEACCESS, sec.DELETEACCESS))
		, INVOKEACCESS =  max(isnull(uso.INVOKEACCESS, sec.INVOKEACCESS))
		, USG_SecAnalysis_Data_AsOf = min(uso.MODIFIEDDATETIME)

		----Columns for debugging/troubleshooting: 
		--, ACCESSLEVEL = max(v.ACCESSLEVEL)
		--, sec.READACCESS
		--, sec.CORRECTACCESS
		--, sec.CREATEACCESS
		--, sec.UPDATEACCESS
		--, sec.DELETEACCESS
		--, sec.INVOKEACCESS
		
		--, uso_READACCESS = uso.READACCESS
		--, uso_CORRECTACCESS = uso.CORRECTACCESS
		--, uso_CREATEACCESS = uso.CREATEACCESS
		--, uso_UPDATEACCESS = uso.UPDATEACCESS
		--, uso_DELETEACCESS = uso.DELETEACCESS
		--, uso_INVOKEACCESS = uso.INVOKEACCESS
		--, cnt = count(1)
		--, vCnt = count(distinct v.RECID)
		--, eoCnt = count(distinct eo.RECID)
		--, spCnt = count(distinct sp.RECID)
		--, srpCnt = count(distinct srp.RECID)
		--, srCnt = count(distinct sr.RECID)
		--, usoCnt = count(distinct uso.recID)
		--, secCnt = count(distinct concat(sec.SECURABLETYPE, sec.AOTNAME, sec.AOTCHILDNAME))
		, SecConfig_SecurableType = --Security type from the Security configuration data
		 --Enum: SecurableType
			  case sec.SECURABLETYPE
			  when 0 then ''
			  when 1 then 'MenuItemDisplay'
			  when 2 then 'MenuItemOutput'
			  when 3 then 'MenuItemAction'
			  when 55 then 'WebUrlItem'
			  when 56 then 'WebActionItem'
			  when 57 then 'WebDisplayContentItem'
			  when 58 then 'WebOutputContentItem'
			  when 75 then 'WebManagedContentItem'
			  when 73 then 'WebControl'
			  when 59 then 'WebletItem'
			  when 42 then 'TableField' --this doesn't match Enum
			  when 44 then 'Table' --this doesn't match Enum
			  when 45 then 'ClassMethod'
			  when 76 then 'ServiceOperation'
			  when 11 then 'FormControl'
			  when 82 then 'FormPart'
			  when 81 then 'InfoPart'
			  when 85 then 'SSRSReport'
			  when 18 then 'Report'
			  when 115 then 'CodePermission'
			  when 143 then 'FormDatasource'
			  when 67 then 'DataEntity'
			  when 146 then 'DataEntityMethod'
			  else
				concat(sec.SECURABLETYPE, '-Unknown') 
			  end
		, USG_SecAnalysis_RESOURCETYPE = uso.RESOURCETYPE
		, USG_SecAnalysis_RESOURCE = uso.RESOURCE_
		, USG_SecAnalysis_RESOURCELABEL = uso.RESOURCELABEL
		, v.ENTITLEMENTOBJECT --PK for entry point. Note: we always need to group by this, because different entry points can have different required license combinations. 
		, roleRecID = case when @includeRoles = 1 then sr.RECID end
		, privRecID = case when @includePrivs = 1 then v.SECURITYPRIVILEGE end --v.SECURITYPRIVILEGE
	from LICENSINGPRIVILEGEREQUIREMENTSDETAILEDVIEW v
		left join LICENSINGENTITLEMENTOBJECTS eo on eo.RECID = v.ENTITLEMENTOBJECT
		left join SECURITYPRIVILEGE sp on sp.RECID = v.SECURITYPRIVILEGE
		left join SECURITYROLEPRIVILEGEEXPLODEDGRAPH srp on srp.SECURITYPRIVILEGE = v.SECURITYPRIVILEGE
		left join SECURITYROLE sr on sr.RECID = srp.SECURITYROLE --and @includeRoles = 1
		outer apply ( --we're using an outer apply here because joining was even slower
			--NOTE: for this data to come through correctly, you have to "Rebuild" on the "Security analysis" (UserSecGovRelatedObjects) form
			select distinct so.READACCESS, so.CREATEACCESS, so.UPDATEACCESS, so.DELETEACCESS, so.CORRECTACCESS, so.INVOKEACCESS, so.RESOURCELABEL, so.RESOURCETYPE, so.RESOURCE_
				, DutyIdentifier = case when @includeDuties = 1 then so.DUTYIDENTIFIER end
				, DutyName = case when @includeDuties = 1 then so.DUTYNAME end
				, so.MODIFIEDDATETIME
			from USERSECGOVRELATEDOBJECTS so
			where 1=1
				and (@showLicenseDetails = 1 OR isnull(@dutyName, '') <> '')
				and so.PRIVILEGEIDENTIFIER = sp.IDENTIFIER
				and so.ROLEIDENTIFIER = sr.AOTNAME
				and so.SECURABLETYPE = eo.SECURABLETYPE
				and (@dutyName is null or @dutyName is not null and so.DUTYNAME like @dutyName)
				and (@roleName is null or @roleName is not null and so.ROLENAME like @roleName)
				and (@privName is null or @privName is not null and so.PRIVILEGENAME like @privName)
				and (so.RESOURCE_ = concat(eo.AOTNAME, case when eo.AOTCHILDNAME <> '' then '\' end, eo.AOTCHILDNAME)
					/* Some resources have a prefix added, so we have to account for those: 
					select distinct top 1000 so.SECURABLETYPE, so.RESOURCETYPE, ResourcePrefix = left(so.RESOURCE_, CHARINDEX('\', so.RESOURCE_,0))
					from USERSECGOVRELATEDOBJECTS so
					where so.RESOURCE_ like '% %\%';

					SECURABLETYPE	RESOURCETYPE	ResourcePrefix
					67	Data entity	Data services\
					67	Data entity	Data Management\
					11	Form control	Menu item display\
					11	Form control	Menu item action\
					146	Data entity action	Data services\
					143	Form Data Source	Menu item display\
					*/
					--Note: the query runs faster when searching using reverse than if searching with wildcard in the front.
					or eo.SECURABLETYPE in (67, 11, 146, 143) and reverse(so.RESOURCE_) like reverse(concat('%\', eo.AOTNAME, case when eo.AOTCHILDNAME <> '' then '\' end, eo.AOTCHILDNAME))
					--or eo.SECURABLETYPE in (67, 11, 146, 143) and so.RESOURCE_ like concat('%\', eo.AOTNAME, case when eo.AOTCHILDNAME <> '' then '\' end, eo.AOTCHILDNAME)
				)
				
		) as uso
		left join SECURITYRESOURCEPRIVILEGEPERMISSIONS sec 
			on @showLicenseDetails = 1 --this info isn't needed if not showing details
			and sec.PRIVILEGEIDENTIFIER = sp.IDENTIFIER 
			and sec.AOTNAME = eo.AOTNAME 
			and (sec.AOTCHILDNAME = eo.AOTCHILDNAME 
				or eo.SECURABLETYPE in (67 /*DataEntity*/,146 /*DataEntityMethod*/) and sec.SECURABLETYPE = 44 --DataEntity
				)
			and (eo.SECURABLETYPE = sec.SECURABLETYPE
				or eo.SECURABLETYPE in (67 /*DataEntity*/,146 /*DataEntityMethod*/) and sec.SECURABLETYPE = 44 --DataEntity
			)
	where 1=1
		and v.ENTITLED = 1 --Only keeping the "entitled" rows helps the query run much faster. There should always be at least one License that is entitled for each entry point so we shouldn't miss anything because of this filter. 
		and (@roleName is null or @roleName is not null and sr.NAME like @roleName)
		and (@dutyName is null or @dutyName is not null 
				--and uso.DutyName like @dutyName --this is very slow
				and v.securityprivilege in (select p2.recid
						from SECURITYOBJECTCHILDREREFERENCES r2
							inner join SECURITYDUTY d2 on r2.IDENTIFIER = d2.IDENTIFIER
							inner join SECURITYPRIVILEGE p2 on p2.IDENTIFIER = r2.CHILDIDENTIFIER
						where r2.OBJECTTYPE = 1 --Duty
							and r2.CHILDOBJECTTYPE = 2 --Priv
							and d2.NAME like @dutyName
							)
				and case when @includeDuties = 1 then uso.DutyName end like @dutyName
				)
		and (@privName is null or @privName is not null and sp.NAME like @privName)
		and (@entryPointName is null or @entryPointName is not null and (eo.AOTNAME like @entryPointName or v.AOTNAME like @entryPointName))
		and (@userID is null or @userID is not null 
			and exists(select 1 --UserID = u.ID, RoleAOTName = sr2.AOTNAME, u.OBJECTID
							from SECURITYUSERROLE ru2 
								inner join USERINFO u2 on ru2.USER_ = u2.ID and ru2.PARTITION = u2.PARTITION 
								inner join SECURITYROLE sr2 on sr2.RECID = ru2.SECURITYROLE
							where 1=1
								and ru2.ASSIGNMENTSTATUS = 1 
								and u2.ENABLE = 1
								and u2.ISMICROSOFTACCOUNT = 0
								and u2.ID like @userID
								and sr.RECID = sr2.RECID
				)
		)
		--Checks for Expected vs. Required Licenses
		and (not exists(select 1 from #tblExpectedLicensesInternal el)
			OR exists(select 1 from #tblExpectedLicensesInternal el) 
			and sr.recid in (select el.roleRecID from #tblExpectedLicensesInternal el)
		)
		and (not exists(select 1 from #tblExpectedLicensesInternal el)
			OR @showRoleLevelLicenseDetails = 1 or @showRoleLevelLicenseSummary = 1 --if showing role level licenses, then we want to include everything, not only what is a mismatch
			OR exists(select 1 from #tblExpectedLicensesInternal el) 
			and not exists(select 1 from LICENSINGPRIVILEGEREQUIREMENTSDETAILEDVIEW v2 where v2.ENTITLEMENTOBJECT = v.ENTITLEMENTOBJECT and v2.SECURITYPRIVILEGE = v.SECURITYPRIVILEGE and v2.ENTITLED = 1 and v2.SKUNAME in ((select isnull(el.skuName, '') from #tblExpectedLicensesInternal el where el.skuName is not null and el.roleRecID = sr.RECID)))
		)
	group by v.ENTITLEMENTOBJECT
		--, v.SECURITYPRIVILEGE
		, case when @includePrivs = 1 then v.SECURITYPRIVILEGE end
		--, sp.IDENTIFIER, sp.NAME
		, case when @includePrivs = 1 then sp.IDENTIFIER end
		, case when @includePrivs = 1 then sp.NAME end
		, eo.SECURABLETYPENAME
		, v.AOTNAME
		, case when @includeRoles = 1 then sr.NAME end
		, case when @includeRoles = 1 then sr.AOTNAME end
		, case when @includeRoles = 1 then sr.RECID end
		, eo.SECURABLETYPE, sec.SECURABLETYPE
		, eo.AOTNAME
		, eo.AOTCHILDNAME
		, uso.RESOURCE_
		, uso.RESOURCELABEL
		, uso.RESOURCETYPE
		, case when @includeDuties = 1 then uso.DutyIdentifier end
		, case when @includeDuties = 1 then uso.DutyName end
		
	having (@showRoleLevelLicenseDetails = 1 or @showRoleLevelLicenseSummary = 1 or isnull(@minSKUPriorityGreaterThanOrEqualTo, -1) <= 0 or @minSKUPriorityGreaterThanOrEqualTo > 0 and min(v.PRIORITY) >= @minSKUPriorityGreaterThanOrEqualTo)
)
select 
	r.*
	--These columns will tell you if you customized in the UI via the Security Configuration form, but not if you customized via X++/Visual Studio metadata via customization. 
	, dutyIsCustomizedInUI = case when @includeDuties = 1 and r.dutyID <> '' then 
							case when exists(select 1 from SECURITYDUTYCUSTOMIZEDISKOBJECT ro where ro.IDENTIFIER = r.dutyID) 
								or exists(select 1 from SECURITYDUTYOBJECT ro where ro.IDENTIFIER = r.dutyID) 
							then 1 else 0 end end
	, privIsCustomizedInUI = case when @includePrivs = 1 and r.PrivID <> '' then 
							case when exists(select 1 from SECURITYPRIVILEGECUSTOMIZEDISKOBJECT ro where ro.IDENTIFIER = r.PrivID) 
								or exists(select 1 from SECURITYPRIVILEGEOBJECT ro where ro.IDENTIFIER = r.PrivID) 
							then 1 else 0 end end
	, roleIsCustomizedInUI = case when @includeRoles = 1 and r.RoleAOTName <> '' then 
							case when exists(select 1 from SECURITYROLECUSTOMIZEDISKOBJECT ro where ro.IDENTIFIER = r.RoleAOTName) 
								or exists(select 1 from SECURITYROLEOBJECT ro where ro.IDENTIFIER = r.RoleAOTName) 
							then 1 else 0 end end
into #tmpLicDetails
from ctePrivRoles r 
where 1=1
option (recompile)
;


--===========================================================================
if @showRoleLevelLicenseDetails = 1 or @showRoleLevelLicenseSummary = 1
begin
if @print = 1
begin
	print 'Getting distinct license groups by role...';
end;
select r.RoleName, r.RoleAOTName
	--, UserID = isnull(ul.UserID, '')
	, r.minRequiredLicense
	, r.minPriority
	, allEntitledLicenses = 
		concat(
		  case when r.Finance = 1 then 'Finance; ' end
		, case when r.[Supply Chain Management] = 1 then 'Supply Chain Management; ' end
		, case when r.[Project Operations] = 1 then 'Project Operations; ' end
		, case when r.[Operations - Activity] = 1 then 'Operations - Activity; ' end
		, case when r.[Team Members] = 1 then 'Team Members; ' end
		, case when r.[Human Resources] = 1 then 'Human Resources; ' end
		, case when r.[Human Resources Self Service] = 1 then 'Human Resources Self Service; ' end
		, case when r.Commerce = 1 then 'Commerce; ' end
		, case when r.[Finance Premium] = 1 then 'Finance Premium; ' end
		, case when r.[Supply Chain Management Premium] = 1 then 'Supply Chain Management Premium; ' end
		, case when r.[None] = 1 then 'None; ' end
		)
	, licenseOptionsCount = 
			  r.Finance
			+ r.[Supply Chain Management]
			+ r.[Project Operations]
			+ r.[Operations - Activity]
			+ r.[Team Members]
			+ r.[Human Resources]
			+ r.[Human Resources Self Service]
			+ r.Commerce
			+ r.[Finance Premium]
			+ r.[Supply Chain Management Premium]
			+ r.[None]

	, r.Finance
	, r.[Supply Chain Management]
	, r.[Project Operations]
	, r.[Operations - Activity]
	, r.[Team Members]
	, r.[Human Resources]
	, r.[Human Resources Self Service]
	, r.Commerce
	, r.[Finance Premium]
	, r.[Supply Chain Management Premium]
	, r.[None]
	, cnt_EntitlementObject = count(distinct r.ENTITLEMENTOBJECT)
	, requiredLicenseGroupID = NEWID()
	, processed = 0
	, roleIsCustomizedInUI = max(r.roleIsCustomizedInUI)
into #tmpRoleLicenseCalc
from #tmpLicDetails r 
	--left join (select distinct UserID = u.ID, RoleAOTName = sr.AOTNAME, ru.SECURITYROLE
	--						from SECURITYUSERROLE ru 
	--							inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
	--							inner join SECURITYROLE sr on sr.RECID = ru.SECURITYROLE
	--						where 1=1
	--							and ru.ASSIGNMENTSTATUS = 1 
	--							and u.ENABLE = 1
	--							and u.ISMICROSOFTACCOUNT = 0
	--			) as ul on r.roleRecID = ul.SECURITYROLE
group by r.RoleName, r.RoleAOTName
	--, ul.UserID
	, r.minPriority
	, r.minRequiredLicense
	, r.Finance
	, r.[Supply Chain Management]
	, r.[Project Operations]
	, r.[Operations - Activity]
	, r.[Team Members]
	, r.[Human Resources]
	, r.[Human Resources Self Service]
	, r.Commerce
	, r.[Finance Premium]
	, r.[Supply Chain Management Premium]
	, r.[None]
;

if @showRoleLevelLicenseSummary = 1 or @showRoleUserLevelSummary = 1
begin
if @print = 1
begin
	print 'Pass 1 - roles where a single license covers everything';
end;
with cte as (
select r.RoleName, r.RoleAOTName
	--, r.UserID
	, requiredLicense = stuff(concat(''
			, case when min(r.[None]) = 1 then 'OR None ' 
				when min(r.[Human Resources Self Service]) = 1 then 'OR Human Resources Self Service ' 
				when min(r.[Team Members]) = 1 then 'OR Team Members ' 
				when min(r.[Operations - Activity]) = 1 then 'OR Operations - Activity '
				else concat(''
					, case when min(r.[Human Resources]) = 1 then 'OR Human Resources ' end
					, case when min(r.[Project Operations]) = 1 then 'OR Project Operations ' end
					, case when min(r.[Commerce]) = 1 then 'OR Commerce ' end
					, case when min(r.[Finance]) = 1 then 'OR Finance ' end
					, case when min(r.[Supply Chain Management]) = 1 then 'OR Supply Chain Management ' end
					, case when min(r.[Finance Premium]) = 1 then 'OR Finance Premium ' end
					, case when min(r.[Supply Chain Management Premium]) = 1 then 'OR Supply Chain Management Premium ' end
				)
			end
		),1,3,'')
	, minPriority = --max(r.minPriority) --there are times this is not correct. Need to select based on the records that match everything, as done below.
					(select min(sku.PRIORITY) from LICENSINGALLSKUS sku where sku.SKUNAME in (case when min(r.[None]) = 1 then 'None' end
							, case when min(r.[Human Resources Self Service]) = 1 then 'Human Resources Self Service' end
							, case when min(r.[Team Members]) = 1 then 'Team Members' end
							, case when min(r.[Operations - Activity]) = 1 then 'Operations - Activity' end
							, case when min(r.[Human Resources]) = 1 then 'Human Resources' end
							, case when min(r.[Project Operations]) = 1 then 'Project Operations' end
							, case when min(r.[Commerce]) = 1 then 'Commerce' end
							, case when min(r.[Finance]) = 1 then 'Finance' end
							, case when min(r.[Supply Chain Management]) = 1 then 'Supply Chain Management' end
							, case when min(r.[Finance Premium]) = 1 then 'Finance Premium' end
							, case when min(r.[Supply Chain Management Premium]) = 1 then 'Supply Chain Management Premium' end
						))
	, minRequiredLicense = --(select top 1 sku.SKUNAME from LICENSINGALLSKUS sku where sku.PRIORITY = max(r.minPriority)) --there are time this can be wrong, so need to calc as below instead
					(select top 1 sku.SKUNAME from LICENSINGALLSKUS sku where sku.SKUNAME in (case when min(r.[None]) = 1 then 'None' end
							, case when min(r.[Human Resources Self Service]) = 1 then 'Human Resources Self Service' end
							, case when min(r.[Team Members]) = 1 then 'Team Members' end
							, case when min(r.[Operations - Activity]) = 1 then 'Operations - Activity' end
							, case when min(r.[Human Resources]) = 1 then 'Human Resources' end
							, case when min(r.[Project Operations]) = 1 then 'Project Operations' end
							, case when min(r.[Commerce]) = 1 then 'Commerce' end
							, case when min(r.[Finance]) = 1 then 'Finance' end
							, case when min(r.[Supply Chain Management]) = 1 then 'Supply Chain Management' end
							, case when min(r.[Finance Premium]) = 1 then 'Finance Premium' end
							, case when min(r.[Supply Chain Management Premium]) = 1 then 'Supply Chain Management Premium' end
						)
						order by sku.PRIORITY
						)
	, Finance = min(r.Finance													  )
	, [Supply Chain Management] = min(r.[Supply Chain Management]				  )
	, [Project Operations] = min(r.[Project Operations]						  )
	, [Operations - Activity] = min(r.[Operations - Activity]					  )
	, [Team Members] = min(r.[Team Members]									  )
	, [Human Resources] = min(r.[Human Resources]								  )
	, [Human Resources Self Service] = min(r.[Human Resources Self Service]	  )
	, Commerce = min(r.Commerce												  )
	, [Finance Premium] = min(r.[Finance Premium]								  )
	, [Supply Chain Management Premium] = min(r.[Supply Chain Management Premium])
	, [None] = min(r.[None])
	--, cnt_EntitlementObject = sum(r.cnt_EntitlementObject)
from #tmpRoleLicenseCalc r
group by r.RoleName, r.RoleAOTName
having 1=2
	OR min(r.[None]) = 1 
	OR min(r.[Human Resources Self Service]) = 1 
	OR min(r.[Team Members]) = 1 
	OR min(r.[Operations - Activity]) = 1 
	OR min(r.[Human Resources]) = 1 
	OR min(r.[Project Operations]) = 1 
	OR min(r.[Commerce]) = 1 
	OR min(r.[Finance]) = 1 
	OR min(r.[Supply Chain Management]) = 1 
	OR min(r.[Finance Premium]) = 1 
	OR min(r.[Supply Chain Management Premium]) = 1 
)
select r.RoleName, r.RoleAOTName, r.requiredLicense, r.minPriority, r.minRequiredLicense
	, roleRequiredLicenseCount = 0
	, r.Finance
	, r.[Supply Chain Management]
	, r.[Project Operations]
	, r.[Operations - Activity]
	, r.[Team Members]
	, r.[Human Resources]
	, r.[Human Resources Self Service]
	, r.Commerce
	, r.[Finance Premium]
	, r.[Supply Chain Management Premium]
	, r.[None]
	, passNum = 1
into #tmpRoleLicenseSummary
from cte r
;

update c
set c.processed = 1
from #tmpRoleLicenseCalc c
where exists(select 1 from #tmpRoleLicenseSummary s where s.RoleAOTName = c.RoleAOTName)
;


-------------------------------------------------------------------------------------
--TODO: update to handle 2+ passes to determine ALL possible combinations of licenses. 
if @print = 1
begin
	print 'Pass 2 - Process remaining roles which require multiple licenses';
	print '  NOTE: this may not show all possible combinations of required licenses, but should calculate the most common/likely (and possibly cheapest?) combination';
end;
declare @passNum int = 2;
--unpivot the results to help in analyzing which roles are needed. 
; with cteUnpivot as (
--Non-base licenses (None through Activity) if required will always have only 1 required, so they don't need included here.  
--          select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'None' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[None] = 1
--union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Human Resources Self Service' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Human Resources Self Service] = 1
--union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Team Members' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Team Members] = 1
--union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Operations - Activity' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Operations - Activity] = 1
--union all 
--TODO: REMOVE PROCESSED FILTER HERE (if we add support for @passNum > 2)? Need to figure out how to determine multiple possible combinations
		  select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Human Resources' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Human Resources] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Project Operations' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Project Operations] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Commerce' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Commerce] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Finance' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Finance] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Supply Chain Management' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Supply Chain Management] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Finance Premium' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Finance Premium] = 1
union all select r.RoleName, r.RoleAOTName, r.requiredLicenseGroupID, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject, processed = 0, procByGroup = cast(null as uniqueidentifier), lic = 'Supply Chain Management Premium' from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0 and r.[Supply Chain Management Premium] = 1
)
select * 
into #tmpLicUnpivot
from cteUnpivot p
;

--Debug:
--SELECT * FROM #tmpLicUnpivot order by RoleAOTName, minPriority desc, licenseOptionsCount, requiredLicenseGroupID;
--SELECT r.RoleAOTName, r.RoleName, r.lic, cnt = count(1) FROM #tmpLicUnpivot r GROUP BY r.RoleAOTName, r.RoleName, r.lic
--select top 100 r.RoleName, r.minPriority, r.licenseOptionsCount, r.cnt_EntitlementObject,  r.* from #tmpRoleLicenseCalc r

declare @tmpRoles table(roleAOTName nvarchar(256) not null primary key, roleName nvarchar(512))
declare @tmpReqLic table(licenseName nvarchar(256) not null primary key, licPriority int)
declare @curRoleAOTName nvarchar(256), @curRoleName nvarchar(512);
insert into @tmpRoles(roleAOTName, roleName)
select distinct r.RoleAOTName, r.RoleName from #tmpRoleLicenseCalc r where r.RoleAOTName is not null and r.processed = 0;

declare @rowID uniqueidentifier
	, @requiredLicense nvarchar(256) --is this needed?
	, @minPriority int; 
while exists(select 1 from @tmpRoles)
begin 
	select top 1 @curRoleAOTName = r.roleAOTName, @curRoleName = r.roleName from @tmpRoles r; 
	delete r from @tmpRoles r where r.roleAOTName = @curRoleAOTName;
	if @@ROWCOUNT = 0
	begin
		;throw 50000, 'Error looping through roles for calc - prevent infinite loop.', 1; --this shouldn't happen, but here to prevent infinite loop.
		break;
	end;
	if @print = 1
	begin
		print concat('  Multi-license processing for ', @curRoleName, ' (', @curRoleAOTName, ')');
	end;
	--determine which license combos will satisfy this role
	declare @irole int = 0;
	while exists(select 1 from #tmpLicUnpivot r where r.processed = 0 and r.RoleAOTName = @curRoleAOTName)
	begin
		set @irole += 1;
		if @irole > 1000
		begin
			raiserror('Infinite loop detected', 16, 1);
			break;
		end;
		select top 1 @rowID = r.requiredLicenseGroupID, @minPriority = r.minPriority, @requiredLicense = (select sku.SKUNAME from LICENSINGALLSKUS sku where sku.PRIORITY = r.minPriority)
		from #tmpLicUnpivot r
		where r.RoleAOTName = @curRoleAOTName
			and r.processed = 0
		order by r.licenseOptionsCount, r.minPriority desc, r.cnt_EntitlementObject desc
		;

		insert into @tmpReqLic(licenseName, licPriority)
		values (@requiredLicense, @minPriority);

		;with cte as (
			select distinct r.requiredLicenseGroupID
			from #tmpLicUnpivot r
			where r.RoleAOTName = @curRoleAOTName
				and r.processed = 0
				and r.lic = @requiredLicense
		)
		update r set r.processed = 1, r.procByGroup = case when r.requiredLicenseGroupID <> @rowID then @rowID end
		from #tmpLicUnpivot r
			inner join cte t on r.requiredLicenseGroupID = t.requiredLicenseGroupID
		where r.RoleAOTName = @curRoleAOTName
			and r.processed = 0
		;
	end;

	insert into #tmpRoleLicenseSummary(RoleAOTName, RoleName, minPriority, minRequiredLicense, requiredLicense, roleRequiredLicenseCount, passNum)
	select @curRoleAOTName, @curRoleName, r.licPriority, r.licenseName, r.licenseName, 0, @passNum
	from @tmpReqLic r
	;

	delete from @tmpReqLic;

end; --end multi-lic calc

update r set r.roleRequiredLicenseCount = (select count(1) from #tmpRoleLicenseSummary r2 where r2.RoleAOTName = r.RoleAOTName)
from #tmpRoleLicenseSummary r
;

update r set 
	  r.[None] = case when r.minRequiredLicense = 'None' then 1 else 0 end
	, r.[Human Resources Self Service] = case when r.minRequiredLicense = 'Human Resources Self Service' then 1 else 0 end
	, r.[Team Members] = case when r.minRequiredLicense = 'Team Members' then 1 else 0 end
	, r.[Operations - Activity] = case when r.minRequiredLicense = 'Operations - Activity' then 1 else 0 end
	, r.[Human Resources] = case when r.minRequiredLicense = 'Human Resources' then 1 else 0 end
	, r.[Project Operations] = case when r.minRequiredLicense = 'Project Operations' then 1 else 0 end
	, r.[Commerce] = case when r.minRequiredLicense = 'Commerce' then 1 else 0 end
	, r.[Finance] = case when r.minRequiredLicense = 'Finance' then 1 else 0 end
	, r.[Supply Chain Management] = case when r.minRequiredLicense = 'Supply Chain Management' then 1 else 0 end
	, r.[Finance Premium] = case when r.minRequiredLicense = 'Finance Premium' then 1 else 0 end
	, r.[Supply Chain Management Premium] = case when r.minRequiredLicense = 'Supply Chain Management Premium' then 1 else 0 end
from #tmpRoleLicenseSummary r
where r.roleRequiredLicenseCount > 1
	and r.Finance is null --the value for each license type column haven't been set yet
;

if @showRoleLevelLicenseSummary = 1
begin
select RoleLevelLicenseSummary=''
	, [matchesExpectedLicense?] = 
		case 
		when not exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuName <> '')
		then null
		when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuPriority = r.minPriority)
		then 1
		--when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and (r.requiredLicense like concat(l.skuName, ' OR %') or r.requiredLicense like concat('% OR ', l.skuName)))
		--then 1
		else 0 
		end
	, [coversExpectedLicense?] = 
		case 
		when not exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuName <> '')
		then null
		when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName 
							and (l.skuPriority = r.minPriority 
								OR (--A base license that covers a lower license
									r.minPriority < l.skuPriority 
									and (r.minPriority <= (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Operations - Activity')
										--Premium licenses should cover non-premium
										or r.minPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Finance')
											and l.skuPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Finance Premium')
										or r.minPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Supply Chain Management')
											and l.skuPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Supply Chain Management Premium')
										)
									)
								)
					)
		then 1
		when exists(select 1 from #tblExpectedLicensesInternal l 
					where l.roleAOTName = r.RoleAOTName 
					and (r.requiredLicense like concat(l.skuName, ' OR %') 
						or r.requiredLicense like concat('% OR ', l.skuName))
						)
		then 1
		else 0 
		end
	, ExpectedLicenses = 
		case 
		when not exists(select 1 from #tblExpectedLicensesInternal)
		then null
		--when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuPriority = r.minPriority)
		--then 1
		else stuff((select distinct concat('; ', l.skuName) from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName order by 1 for xml path('')), 1, 2, '')
		end
	, enabledUserCount = (select count(ru.USER_) 
					from SECURITYUSERROLE ru 
						inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
						inner join SECURITYROLE sr on ru.SECURITYROLE = sr.RECID
					where sr.AOTNAME = r.RoleAOTName 
						and ru.ASSIGNMENTSTATUS = 1 --Enabled
						and u.ENABLE = 1
						and u.ISMICROSOFTACCOUNT = 0
					)
	, r.* 
from #tmpRoleLicenseSummary r
order by 
	[coversExpectedLicense?], [matchesExpectedLicense?], 
	r.RoleName, r.RoleAOTName;
end; 
--for debugging:
--select tmpLicUnpivot='',r.* from #tmpLicUnpivot r order by r.RoleName, r.RoleAOTName, r.minPriority desc, r.licenseOptionsCount, r.cnt_EntitlementObject desc


if @showRoleUserLevelSummary = 1
begin
	;with cte as (
		select RoleUserLevelLicenseSummary=''
			, [matchesExpectedLicense?] = 
				case 
				when not exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuName <> '')
				then null
				when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuPriority = r.minPriority)
				then 1
				--when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and (r.requiredLicense like concat(l.skuName, ' OR %') or r.requiredLicense like concat('% OR ', l.skuName)))
				--then 1
				else 0 
				end
			, [coversExpectedLicense?] = 
				case 
				when not exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuName <> '')
				then null
				when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName 
									and (l.skuPriority = r.minPriority 
										OR (--A base license that covers a lower license
											r.minPriority < l.skuPriority 
											and (r.minPriority <= (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Operations - Activity')
												--Premium licenses should cover non-premium
												or r.minPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Finance')
													and l.skuPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Finance Premium')
												or r.minPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Supply Chain Management')
													and l.skuPriority = (select sku.PRIORITY from LICENSINGALLSKUS sku where sku.SKUNAME = 'Supply Chain Management Premium')
												)
											)
										)
							)
				then 1
				when exists(select 1 from #tblExpectedLicensesInternal l 
							where l.roleAOTName = r.RoleAOTName 
							and (r.requiredLicense like concat(l.skuName, ' OR %') 
								or r.requiredLicense like concat('% OR ', l.skuName))
								)
				then 1
				else 0 
				end
			, ExpectedLicenses = 
				case 
				when not exists(select 1 from #tblExpectedLicensesInternal)
				then null
				--when exists(select 1 from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName and l.skuPriority = r.minPriority)
				--then 1
				else stuff((select distinct concat('; ', l.skuName) from #tblExpectedLicensesInternal l where l.roleAOTName = r.RoleAOTName order by 1 for xml path('')), 1, 2, '')
				end
			, enabledUserCount = (select count(ru.USER_) 
							from SECURITYUSERROLE ru 
								inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
								inner join SECURITYROLE sr on ru.SECURITYROLE = sr.RECID
							where sr.AOTNAME = r.RoleAOTName 
								and ru.ASSIGNMENTSTATUS = 1 --Enabled
								and u.ENABLE = 1
								and u.ISMICROSOFTACCOUNT = 0
							)
			, ul.UserID
			, User_ObjectID = ul.OBJECTID
			, r.* 
		from #tmpRoleLicenseSummary r
			left join (select UserID = u.ID, RoleAOTName = sr.AOTNAME, u.OBJECTID
							from SECURITYUSERROLE ru 
								inner join USERINFO u on ru.USER_ = u.ID and ru.PARTITION = u.PARTITION 
								inner join SECURITYROLE sr on sr.RECID = ru.SECURITYROLE
							where 1=1
								and ru.ASSIGNMENTSTATUS = 1 
								and u.ENABLE = 1
								and u.ISMICROSOFTACCOUNT = 0
				) as ul on r.RoleAOTName = ul.RoleAOTName
		where 1=1
			and (@userID is null or @userID is not null and ul.UserID like @userID)
	)
	select * 
	from cte r
	where 1=1
		--and r.[coversExpectedLicense?] = 0
	order by r.UserID, [coversExpectedLicense?], [matchesExpectedLicense?], r.RoleName, r.RoleAOTName;

end; --user role level

--**/
end; --show role or role user summary


if @showRoleLevelLicenseDetails = 1
begin
	select RoleLevelLicenseDetails='', r.* 
	from #tmpRoleLicenseCalc r
	order by r.RoleName, r.RoleAOTName
		, r.minPriority desc
		, r.minRequiredLicense
		, r.licenseOptionsCount
		, r.Finance
		, r.[Supply Chain Management]
		, r.[Project Operations]
		, r.[Operations - Activity]
		, r.[Team Members]
		, r.[Human Resources]
		, r.[Human Resources Self Service]
		, r.Commerce
		, r.[Finance Premium]
		, r.[Supply Chain Management Premium]
		, r.[None]
	;
end;

end; --show either role level 

if @showLicenseDetails = 1
begin
	select LicenseDetails='',r.* 
	from #tmpLicDetails r 
	where 1=1
		and (not exists(select 1 from #tblExpectedLicensesInternal el)
				OR exists(select 1 from #tblExpectedLicensesInternal el) 
				and not exists(select 1 from LICENSINGPRIVILEGEREQUIREMENTSDETAILEDVIEW v2 where v2.ENTITLEMENTOBJECT = r.ENTITLEMENTOBJECT and v2.SECURITYPRIVILEGE = r.privRecID and v2.ENTITLED = 1 and v2.SKUNAME in ((select isnull(el.skuName, '') from #tblExpectedLicensesInternal el where el.skuName is not null and el.roleRecID = r.roleRecID)))
			)
		and (isnull(@minSKUPriorityGreaterThanOrEqualTo, -1) <= 0 or @minSKUPriorityGreaterThanOrEqualTo > 0 and r.minPriority >= @minSKUPriorityGreaterThanOrEqualTo)
	order by 
		--r.ENTITLEMENTOBJECT,
		r.RoleName, 
		r.minPriority desc, --show more expense required licenses first in the list
		r.duty,
		r.PrivName
		, r.SECURABLETYPENAME
		, r.EntryPoint_AOTNAME
	;
end; --end @showLicenseDetails


/**
--Troubleshooting/ Testing

--Get all unique possible combinations of base license combinations, excluding Premium
;with cte as (
	select * 
	from LICENSINGALLSKUS sku
	where sku.GROUPNAME in ('Base - Commerce, Finance, Supply Chain Management','Base - Human Resources, Project Operations')
		and sku.SKUNAME not like '%Premium'
)
, cteRecurse as (
	select Combination = cast(cte.SKUNAME  as nvarchar(max))
		, levelNum = 1
		, cte.PRIORITY as LastPriority
	from cte --root	
	union all 
	select concat(r.Combination, ', ', t.SKUNAME)
		, r.levelNum + 1
		, t.PRIORITY
	from cteRecurse r
		inner join cte t on t.PRIORITY < r.LastPriority --to keep unique combinations
)
select BaseLicensePossibleCombinations = '', r.* 
from cteRecurse r
order by r.Combination, r.levelNum, r.lastPriority
;




--============================================================
--Get sample entitled objects for testing custom roles. 
--MenuItemDisplay	VENDEDITINVOICE - SCM or Finance
--MenuItemDisplay	PROJCOSTPRICEHOUR - SCM or Proj ops 
--MenuItemDisplay	PROJREVERSETRANS - Finance OR Proj Ops
select top 100  v.ENTITLEMENTOBJECT
	, eo.SECURABLETYPENAME
	, eo.AOTNAME
	, eo.AOTCHILDNAME
	, v.ACCESSLEVEL
	, [Finance] = max(case when v.skuname = 'Finance' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Supply Chain Management] = max(case when v.skuname = 'Supply Chain Management' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Project Operations] = max(case when v.skuname = 'Project Operations' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Operations - Activity] = max(case when v.skuname = 'Operations - Activity' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Team Members] = max(case when v.skuname = 'Team Members' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Human Resources] = max(case when v.skuname = 'Human Resources' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Human Resources Self Service] = max(case when v.skuname = 'Human Resources Self Service' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Commerce] = max(case when v.skuname = 'Commerce' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Finance Premium] = max(case when v.skuname = 'Finance Premium' and v.ENTITLED = 1 then 1 else 0 end) 
		, [Supply Chain Management Premium] = max(case when v.skuname = 'Supply Chain Management Premium' and v.ENTITLED = 1 then 1 else 0 end) 
		, [None] = max(case when v.skuname = 'None' and v.ENTITLED = 1 then 1 else 0 end) 
from LICENSINGPRIVILEGEREQUIREMENTSDETAILEDVIEW v
	left join LICENSINGENTITLEMENTOBJECTS eo on v.ENTITLEMENTOBJECT = eo.RECID
where v.ENTITLED = 1
group by v.ENTITLEMENTOBJECT, eo.SECURABLETYPENAME
	, eo.AOTNAME
	, eo.AOTCHILDNAME, v.ACCESSLEVEL
having 1=2
	OR
		    max(case when v.skuname = 'Finance' and v.ENTITLED = 1 then 1 else 0 end)  = 0
		and max(case when v.skuname = 'Supply Chain Management' and v.ENTITLED = 1 then 1 else 0 end) = 1
		and max(case when v.skuname = 'Project Operations' and v.ENTITLED = 1 then 1 else 0 end) = 1
		and max(case when v.skuname = 'Operations - Activity' and v.ENTITLED = 1 then 1 else 0 end) = 0
		and max(case when v.skuname = 'Team Members' and v.ENTITLED = 1 then 1 else 0 end) = 0
		and max(case when v.skuname = 'Human Resources' and v.ENTITLED = 1 then 1 else 0 end) = 0
		and max(case when v.skuname = 'Human Resources Self Service' and v.ENTITLED = 1 then 1 else 0 end) = 0
		and max(case when v.skuname = 'Commerce' and v.ENTITLED = 1 then 1 else 0 end) = 0
		--and max(case when v.skuname = 'Finance Premium' and v.ENTITLED = 1 then 1 else 0 end) = 0
		--and max(case when v.skuname = 'Supply Chain Management Premium' and v.ENTITLED = 1 then 1 else 0 end) = 0
		and max(case when v.skuname = 'None' and v.ENTITLED = 1 then 1 else 0 end) = 0


--=================================================================
--Insert missing records into LICENSINGPRIVILEGEPERMISSIONS, for when you make security updates in the UI and don't want to wait for a refresh.
--		This works as long as you don't have new ENTITLEMENTOBJECTs involved.
begin tran;

	insert into LICENSINGPRIVILEGEPERMISSIONS(ENTITLEMENTOBJECT, SECURITYPRIVILEGE, ACCESSLEVEL)
	select 
		 ENTITLEMENTOBJECT = eo.RECID
		, SECURITYPRIVILEGE = p2.recid
		, accessLevel = 
			case when pp.UPDATEACCESS = 1 or pp.CREATEACCESS =1 or  pp.DELETEACCESS = 1 or pp.INVOKEACCESS = 1 then 2 
			when pp.READACCESS = 1 then 1
			else null end
		--, pp.AOTNAME, pp.AOTCHILDNAME
		--, eo.SECURABLETYPE, eo.SECURABLETYPENAME, pp.SECURABLETYPE
		--, privName = p2.NAME
		--, pp.UPDATEACCESS, pp.CREATEACCESS, pp.DELETEACCESS, pp.INVOKEACCESS , pp.READACCESS
		--, r2.*
	from SECURITYPRIVILEGE p2 
		inner join SECURITYRESOURCEPRIVILEGEPERMISSIONS pp on p2.IDENTIFIER = pp.PRIVILEGEIDENTIFIER
		inner join LICENSINGENTITLEMENTOBJECTS eo on eo.AOTNAME = pp.AOTNAME and eo.AOTCHILDNAME = pp.AOTCHILDNAME and eo.SECURABLETYPE = pp.SECURABLETYPE
	where 1=1
		--and p2.NAME like 'BradTest%'
		and not exists(select 1 from LICENSINGPRIVILEGEPERMISSIONS lp where lp.SECURITYPRIVILEGE = p2.RECID and lp.ENTITLEMENTOBJECT = eo.RECID)
		and (
			pp.UPDATEACCESS = 1 or pp.CREATEACCESS =1 or  pp.DELETEACCESS = 1 or pp.INVOKEACCESS = 1 or pp.READACCESS = 1
		)
	;

rollback;

--================================================

--last data refresh date: 
--2025-08-05 21:11:08.330	2025-08-05 17:16:59.000	2025-08-05 17:16:59.000	17471
--2025-08-11 16:00:15.553	2025-08-11 11:17:12.000	2025-08-11 11:17:12.000	17471
--2025-08-11 18:28:22.890	2025-08-11 17:16:48.000	2025-08-11 17:16:48.000	17471
select LICENSINGELEMENTSREQUIRINGENTITLEMENT = GETUTCDATE(), minDate =  min(t.MODIFIEDDATETIME), maxDate = max(t.MODIFIEDDATETIME), cnt = count(1) 
	from LICENSINGELEMENTSREQUIRINGENTITLEMENT t 

---*/