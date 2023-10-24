/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  Entity,
  RELATION_API_CONSUMED_BY,
  RELATION_API_PROVIDED_BY,
  RELATION_CONSUMES_API,
  RELATION_DEPENDENCY_OF,
  RELATION_DEPENDS_ON,
  RELATION_HAS_PART,
  RELATION_PART_OF,
  RELATION_PROVIDES_API,
} from '@backstage/catalog-model';
import { EmptyState, InfoCard } from '@backstage/core-components';
import { EntityAdrContent, isAdrAvailable } from '@backstage/plugin-adr';
import {
  EntityApiDefinitionCard,
  EntityConsumedApisCard,
  EntityConsumingComponentsCard,
  EntityHasApisCard,
  EntityProvidedApisCard,
  EntityProvidingComponentsCard,
} from '@backstage/plugin-api-docs';
import {
  EntityAzurePipelinesContent,
  EntityAzureGitTagsContent,
  EntityAzurePullRequestsContent,
  isAzureDevOpsAvailable,
  isAzurePipelinesAvailable,
  EntityAzureReadmeCard,
} from '@backstage/plugin-azure-devops';
import {
  isOctopusDeployAvailable,
  EntityOctopusDeployContent,
} from '@backstage/plugin-octopus-deploy';
import { EntityBadgesDialog } from '@backstage/plugin-badges';
import {
  EntityAboutCard,
  EntityDependsOnComponentsCard,
  EntityDependsOnResourcesCard,
  EntityHasComponentsCard,
  EntityHasResourcesCard,
  EntityHasSubcomponentsCard,
  EntityHasSystemsCard,
  EntityLayout,
  EntityLinksCard,
  EntityLabelsCard,
  EntityOrphanWarning,
  EntityProcessingErrorsPanel,
  EntitySwitch,
  hasCatalogProcessingErrors,
  isComponentType,
  isKind,
  isOrphan,
  hasLabels,
  hasRelationWarnings,
  EntityRelationWarning,
} from '@backstage/plugin-catalog';
import {
  Direction,
  EntityCatalogGraphCard,
} from '@backstage/plugin-catalog-graph';
import {
  EntityCircleCIContent,
  isCircleCIAvailable,
} from '@backstage/plugin-circleci';
import {
  EntityCloudbuildContent,
  isCloudbuildAvailable,
} from '@backstage/plugin-cloudbuild';
import { EntityCodeCoverageContent } from '@backstage/plugin-code-coverage';
import {
  DynatraceTab,
  isDynatraceAvailable,
} from '@backstage/plugin-dynatrace';
import {
  EntityFeedbackResponseContent,
  EntityLikeDislikeRatingsCard,
  LikeDislikeButtons,
} from '@backstage/plugin-entity-feedback';
import {
  EntityGithubActionsContent,
  EntityRecentGithubActionsRunsCard,
  isGithubActionsAvailable,
} from '@backstage/plugin-github-actions';
import {
  EntityJenkinsContent,
  EntityLatestJenkinsRunCard,
  isJenkinsAvailable,
} from '@backstage/plugin-jenkins';
import { EntityKafkaContent } from '@backstage/plugin-kafka';
import { EntityKubernetesContent } from '@backstage/plugin-kubernetes';
import {
  isKubernetesClusterAvailable,
  EntityKubernetesClusterContent,
} from '@backstage/plugin-kubernetes-cluster';
import {
  EntityLastLighthouseAuditCard,
  EntityLighthouseContent,
  isLighthouseAvailable,
} from '@backstage/plugin-lighthouse';
import {
  EntityGroupProfileCard,
  EntityMembersListCard,
  EntityOwnershipCard,
  EntityUserProfileCard,
} from '@backstage/plugin-org';
import {
  EntityNomadAllocationListTable,
  EntityNomadJobVersionListCard,
  isNomadAllocationsAvailable,
  isNomadJobIDAvailable,
} from '@backstage/plugin-nomad';
import {
  EntityPagerDutyCard,
  isPagerDutyAvailable,
} from '@backstage/plugin-pagerduty';
import { EntityPlaylistDialog } from '@backstage/plugin-playlist';
import {
  EntityRollbarContent,
  isRollbarAvailable,
} from '@backstage/plugin-rollbar';
import { PuppetDbPage, isPuppetDbAvailable } from '@backstage/plugin-puppetdb';
import { EntitySentryContent } from '@backstage/plugin-sentry';
import { EntityTechdocsContent } from '@backstage/plugin-techdocs';
import { EntityTechInsightsScorecardCard } from '@backstage/plugin-tech-insights';
import { EntityTodoContent } from '@backstage/plugin-todo';
import { Button, Grid } from '@material-ui/core';
import BadgeIcon from '@material-ui/icons/CallToAction';
import PlaylistAddIcon from '@material-ui/icons/PlaylistAdd';

import {
  EntityGithubInsightsContent,
  EntityGithubInsightsLanguagesCard,
  EntityGithubInsightsReadmeCard,
  EntityGithubInsightsReleasesCard,
  isGithubInsightsAvailable,
} from '@roadiehq/backstage-plugin-github-insights';
import {
  EntityGithubPullRequestsContent,
  EntityGithubPullRequestsOverviewCard,
  isGithubPullRequestsAvailable,
} from '@roadiehq/backstage-plugin-github-pull-requests';
import {
  EntityTravisCIContent,
  EntityTravisCIOverviewCard,
  isTravisciAvailable,
} from '@roadiehq/backstage-plugin-travis-ci';
import {
  EntityBuildkiteContent,
  isBuildkiteAvailable,
} from '@roadiehq/backstage-plugin-buildkite';
import {
  isNewRelicDashboardAvailable,
  EntityNewRelicDashboardContent,
  EntityNewRelicDashboardCard,
} from '@backstage/plugin-newrelic-dashboard';
import { EntityGoCdContent, isGoCdAvailable } from '@backstage/plugin-gocd';
import { EntityScoreCardContent } from '@oriflame/backstage-plugin-score-card';

import React, { ReactNode, useMemo, useState } from 'react';

import { TechDocsAddons } from '@backstage/plugin-techdocs-react';
import {
  TextSize,
  ReportIssue,
  LightBox,
} from '@backstage/plugin-techdocs-module-addons-contrib';
import { EntityCostInsightsContent } from '@backstage/plugin-cost-insights';
import {
  isLinguistAvailable,
  EntityLinguistCard,
} from '@backstage/plugin-linguist';

const customEntityFilterKind = ['Component', 'API', 'System'];

const EntityLayoutWrapper = (props: { children?: ReactNode }) => {
  const [badgesDialogOpen, setBadgesDialogOpen] = useState(false);
  const [playlistDialogOpen, setPlaylistDialogOpen] = useState(false);

  const extraMenuItems = useMemo(() => {
    return [
      {
        title: 'Badges',
        Icon: BadgeIcon,
        onClick: () => setBadgesDialogOpen(true),
      },
      {
        title: 'Add to playlist',
        Icon: PlaylistAddIcon,
        onClick: () => setPlaylistDialogOpen(true),
      },
    ];
  }, []);

  return (
    <>
      <EntityLayout
        UNSTABLE_extraContextMenuItems={extraMenuItems}
        UNSTABLE_contextMenuOptions={{
          disableUnregister: 'visible',
        }}
      >
        {props.children}
      </EntityLayout>
      <EntityBadgesDialog
        open={badgesDialogOpen}
        onClose={() => setBadgesDialogOpen(false)}
      />
      <EntityPlaylistDialog
        open={playlistDialogOpen}
        onClose={() => setPlaylistDialogOpen(false)}
      />
    </>
  );
};

const techdocsContent = (
  <EntityTechdocsContent>
    <TechDocsAddons>
      <TextSize />
      <ReportIssue />
      <LightBox />
    </TechDocsAddons>
  </EntityTechdocsContent>
);

/**
 * NOTE: This page is designed to work on small screens such as mobile devices.
 * This is based on Material UI Grid. If breakpoints are used, each grid item must set the `xs` prop to a column size or to `true`,
 * since this does not default. If no breakpoints are used, the items will equitably share the available space.
 * https://material-ui.com/components/grid/#basic-grid.
 */

export const cicdContent = (
  <EntitySwitch>
    <EntitySwitch.Case if={isJenkinsAvailable}>
      <EntityJenkinsContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isBuildkiteAvailable}>
      <EntityBuildkiteContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isCircleCIAvailable}>
      <EntityCircleCIContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isCloudbuildAvailable}>
      <EntityCloudbuildContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isTravisciAvailable}>
      <EntityTravisCIContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isGoCdAvailable}>
      <EntityGoCdContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isGithubActionsAvailable}>
      <EntityGithubActionsContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isAzurePipelinesAvailable}>
      <EntityAzurePipelinesContent defaultLimit={25} />
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isOctopusDeployAvailable}>
      <EntityOctopusDeployContent defaultLimit={25} />
    </EntitySwitch.Case>

    <EntitySwitch.Case>
      <EmptyState
        title="No CI/CD available for this entity"
        missing="info"
        description="You need to add an annotation to your component if you want to enable CI/CD for it. You can read more about annotations in Backstage by clicking the button below."
        action={
          <Button
            variant="contained"
            color="primary"
            href="https://backstage.io/docs/features/software-catalog/well-known-annotations"
          >
            Read more
          </Button>
        }
      />
    </EntitySwitch.Case>
  </EntitySwitch>
);

const cicdCard = (
  <EntitySwitch>
    <EntitySwitch.Case if={isJenkinsAvailable}>
      <Grid item sm={6}>
        <EntityLatestJenkinsRunCard branch="master" variant="gridItem" />
      </Grid>
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isTravisciAvailable as (e: Entity) => boolean}>
      <Grid item sm={6}>
        <EntityTravisCIOverviewCard />
      </Grid>
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isGithubActionsAvailable}>
      <Grid item sm={6}>
        <EntityRecentGithubActionsRunsCard limit={4} variant="gridItem" />
      </Grid>
    </EntitySwitch.Case>
  </EntitySwitch>
);

const entityWarningContent = (
  <>
    <EntitySwitch>
      <EntitySwitch.Case if={isOrphan}>
        <Grid item xs={12}>
          <EntityOrphanWarning />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={hasRelationWarnings}>
        <Grid item xs={12}>
          <EntityRelationWarning />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={hasCatalogProcessingErrors}>
        <Grid item xs={12}>
          <EntityProcessingErrorsPanel />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>
  </>
);

const errorsContent = (
  <EntitySwitch>
    <EntitySwitch.Case if={isRollbarAvailable}>
      <EntityRollbarContent />
    </EntitySwitch.Case>

    <EntitySwitch.Case>
      <EntitySentryContent />
    </EntitySwitch.Case>
  </EntitySwitch>
);

const pullRequestsContent = (
  <EntitySwitch>
    <EntitySwitch.Case if={isAzureDevOpsAvailable}>
      <EntityAzurePullRequestsContent defaultLimit={25} />
    </EntitySwitch.Case>

    <EntitySwitch.Case>
      <EntityGithubPullRequestsContent />
    </EntitySwitch.Case>
  </EntitySwitch>
);

const overviewContent = (
  <Grid container spacing={3} alignItems="stretch">
    {entityWarningContent}
    <Grid item md={6} xs={12}>
      <EntityAboutCard variant="gridItem" />
    </Grid>

    <Grid item md={6} xs={12}>
      <EntityCatalogGraphCard variant="gridItem" height={400} />
    </Grid>

    <EntitySwitch>
      <EntitySwitch.Case if={isPagerDutyAvailable}>
        <Grid item md={6}>
          <EntityPagerDutyCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={isNewRelicDashboardAvailable}>
        <Grid item md={6} xs={12}>
          <EntityNewRelicDashboardCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <Grid item md={4} xs={12}>
      <EntityLinksCard />
    </Grid>

    <EntitySwitch>
      <EntitySwitch.Case if={hasLabels}>
        <Grid item md={4} xs={12}>
          <EntityLabelsCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={isAzureDevOpsAvailable}>
        <Grid item md={6}>
          <EntityAzureReadmeCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <Grid item md={2}>
      <InfoCard title="Rate this entity">
        <LikeDislikeButtons />
      </InfoCard>
    </Grid>

    {cicdCard}

    <EntitySwitch>
      <EntitySwitch.Case if={isGithubInsightsAvailable}>
        <Grid item md={6}>
          <EntityGithubInsightsLanguagesCard />
          <EntityGithubInsightsReleasesCard />
        </Grid>
        <Grid item md={6}>
          <EntityGithubInsightsReadmeCard maxHeight={350} />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={isLighthouseAvailable}>
        <Grid item sm={4}>
          <EntityLastLighthouseAuditCard variant="gridItem" />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={isGithubPullRequestsAvailable}>
        <Grid item sm={4}>
          <EntityGithubPullRequestsOverviewCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <EntitySwitch>
      <EntitySwitch.Case if={isLinguistAvailable}>
        <Grid item md={6}>
          <EntityLinguistCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>

    <Grid item md={8} xs={12}>
      <EntityHasSubcomponentsCard variant="gridItem" />
    </Grid>

    <EntitySwitch>
      <EntitySwitch.Case if={isNomadJobIDAvailable}>
        <Grid item md={6} xs={12}>
          <EntityNomadJobVersionListCard />
        </Grid>
      </EntitySwitch.Case>
    </EntitySwitch>
  </Grid>
);

const serviceEntityPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      {overviewContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/ci-cd" title="CI/CD">
      {cicdContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/errors" title="Errors">
      {errorsContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/api" title="API">
      <Grid container spacing={3} alignItems="stretch">
        <Grid item xs={12} md={6}>
          <EntityProvidedApisCard />
        </Grid>
        <Grid item xs={12} md={6}>
          <EntityConsumedApisCard />
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/dependencies" title="Dependencies">
      <Grid container spacing={3} alignItems="stretch">
        <Grid item xs={12} md={6}>
          <EntityDependsOnComponentsCard variant="gridItem" />
        </Grid>
        <Grid item xs={12} md={6}>
          <EntityDependsOnResourcesCard variant="gridItem" />
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/docs" title="Docs">
      {techdocsContent}
    </EntityLayout.Route>

    <EntityLayout.Route if={isAdrAvailable} path="/adrs" title="ADRS">
      <EntityAdrContent />
    </EntityLayout.Route>

    <EntityLayout.Route
      if={isNewRelicDashboardAvailable}
      path="/newrelic-dashboard"
      title="New Relic Dashboard"
    >
      <EntityNewRelicDashboardContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/kubernetes" title="Kubernetes">
      <EntityKubernetesContent />
    </EntityLayout.Route>

    <EntityLayout.Route
      if={isNomadAllocationsAvailable}
      path="/nomad"
      title="Nomad"
    >
      <EntityNomadAllocationListTable />
    </EntityLayout.Route>

    <EntityLayout.Route path="/pull-requests" title="Pull Requests">
      {pullRequestsContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/code-insights" title="Code Insights">
      <EntityGithubInsightsContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/tech-insights" title="Scorecards">
      <Grid container spacing={3} alignItems="stretch">
        <Grid item xs={12} md={6}>
          <EntityTechInsightsScorecardCard
            title="Scorecard 1"
            description="This is a sample scorecard no. 1"
            checksId={['titleCheck']}
          />
        </Grid>
        <Grid item xs={12} md={6}>
          <EntityTechInsightsScorecardCard
            title="Scorecard 2"
            checksId={['techDocsCheck']}
          />
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/code-coverage" title="Code Coverage">
      <EntityCodeCoverageContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/kafka" title="Kafka">
      <EntityKafkaContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/todos" title="TODOs">
      <EntityTodoContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/costs" title="Costs">
      <EntityCostInsightsContent />
    </EntityLayout.Route>

    <EntityLayout.Route
      path="/dynatrace"
      title="Dynatrace"
      if={isDynatraceAvailable}
    >
      <DynatraceTab />
    </EntityLayout.Route>

    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const websiteEntityPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      {overviewContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/ci-cd" title="CI/CD">
      {cicdContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/lighthouse" title="Lighthouse">
      <EntityLighthouseContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/errors" title="Errors">
      {errorsContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/dependencies" title="Dependencies">
      <Grid container spacing={3} alignItems="stretch">
        <Grid item md={6}>
          <EntityDependsOnComponentsCard variant="gridItem" />
        </Grid>
        <Grid item md={6}>
          <EntityDependsOnResourcesCard variant="gridItem" />
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/docs" title="Docs">
      {techdocsContent}
    </EntityLayout.Route>

    <EntityLayout.Route
      if={isNewRelicDashboardAvailable}
      path="/newrelic-dashboard"
      title="New Relic Dashboard"
    >
      <EntityNewRelicDashboardContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/kubernetes" title="Kubernetes">
      <EntityKubernetesContent />
    </EntityLayout.Route>

    <EntityLayout.Route
      path="/dynatrace"
      title="Dynatrace"
      if={isDynatraceAvailable}
    >
      <DynatraceTab />
    </EntityLayout.Route>

    <EntityLayout.Route
      if={isAzureDevOpsAvailable}
      path="/git-tags"
      title="Git Tags"
    >
      <EntityAzureGitTagsContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/pull-requests" title="Pull Requests">
      {pullRequestsContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/code-insights" title="Code Insights">
      <EntityGithubInsightsContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/code-coverage" title="Code Coverage">
      <EntityCodeCoverageContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/todos" title="TODOs">
      <EntityTodoContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const defaultEntityPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      {overviewContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/docs" title="Docs">
      {techdocsContent}
    </EntityLayout.Route>

    <EntityLayout.Route path="/todos" title="TODOs">
      <EntityTodoContent />
    </EntityLayout.Route>

    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const componentPage = (
  <EntitySwitch>
    <EntitySwitch.Case if={isComponentType('service')}>
      {serviceEntityPage}
    </EntitySwitch.Case>

    <EntitySwitch.Case if={isComponentType('website')}>
      {websiteEntityPage}
    </EntitySwitch.Case>

    <EntitySwitch.Case>{defaultEntityPage}</EntitySwitch.Case>
  </EntitySwitch>
);

const apiPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3}>
        {entityWarningContent}
        <Grid item md={6} xs={12}>
          <EntityAboutCard />
        </Grid>
        <Grid item md={6} xs={12}>
          <EntityCatalogGraphCard variant="gridItem" height={400} />
        </Grid>
        <Grid item xs={12}>
          <Grid container>
            <Grid item xs={12} md={6}>
              <EntityProvidingComponentsCard />
            </Grid>
            <Grid item xs={12} md={6}>
              <EntityConsumingComponentsCard />
            </Grid>
            <Grid item md={2}>
              <InfoCard title="Rate this entity">
                <LikeDislikeButtons />
              </InfoCard>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/definition" title="Definition">
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <EntityApiDefinitionCard />
        </Grid>
      </Grid>
    </EntityLayout.Route>

    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const userPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3}>
        {entityWarningContent}
        <Grid item xs={12} md={6}>
          <EntityUserProfileCard variant="gridItem" />
        </Grid>
        <Grid item xs={12} md={6}>
          <EntityOwnershipCard
            variant="gridItem"
            entityFilterKind={customEntityFilterKind}
          />
        </Grid>
        <Grid item xs={12}>
          <EntityLikeDislikeRatingsCard />
        </Grid>
      </Grid>
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const groupPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3}>
        {entityWarningContent}
        <Grid item xs={12} md={6}>
          <EntityGroupProfileCard variant="gridItem" />
        </Grid>
        <Grid item xs={12} md={6}>
          <EntityOwnershipCard
            variant="gridItem"
            entityFilterKind={customEntityFilterKind}
          />
        </Grid>
        <Grid item xs={12}>
          <EntityMembersListCard />
        </Grid>
        <Grid item xs={12}>
          <EntityLikeDislikeRatingsCard />
        </Grid>
      </Grid>
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const systemPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3} alignItems="stretch">
        {entityWarningContent}
        <Grid item md={6}>
          <EntityAboutCard variant="gridItem" />
        </Grid>
        <Grid item md={6} xs={12}>
          <EntityCatalogGraphCard variant="gridItem" height={400} />
        </Grid>
        <Grid item md={6}>
          <EntityHasComponentsCard variant="gridItem" />
        </Grid>
        <Grid item md={6}>
          <EntityHasApisCard variant="gridItem" />
        </Grid>
        <Grid item md={6}>
          <EntityHasResourcesCard variant="gridItem" />
        </Grid>
        <Grid item md={2}>
          <InfoCard title="Rate this entity">
            <LikeDislikeButtons />
          </InfoCard>
        </Grid>
      </Grid>
    </EntityLayout.Route>
    <EntityLayout.Route path="/score" title="Score">
      <Grid container spacing={3} alignItems="stretch">
        <Grid item xs={12}>
          <EntityScoreCardContent />
        </Grid>
      </Grid>
    </EntityLayout.Route>
    <EntityLayout.Route path="/diagram" title="Diagram">
      <EntityCatalogGraphCard
        variant="gridItem"
        direction={Direction.TOP_BOTTOM}
        title="System Diagram"
        height={700}
        relations={[
          RELATION_PART_OF,
          RELATION_HAS_PART,
          RELATION_API_CONSUMED_BY,
          RELATION_API_PROVIDED_BY,
          RELATION_CONSUMES_API,
          RELATION_PROVIDES_API,
          RELATION_DEPENDENCY_OF,
          RELATION_DEPENDS_ON,
        ]}
        unidirectional={false}
      />
    </EntityLayout.Route>
    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const domainPage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3} alignItems="stretch">
        {entityWarningContent}
        <Grid item md={6}>
          <EntityAboutCard variant="gridItem" />
        </Grid>
        <Grid item md={6} xs={12}>
          <EntityCatalogGraphCard variant="gridItem" height={400} />
        </Grid>
        <Grid item md={6}>
          <EntityHasSystemsCard variant="gridItem" />
        </Grid>
        <Grid item md={2}>
          <InfoCard title="Rate this entity">
            <LikeDislikeButtons />
          </InfoCard>
        </Grid>
      </Grid>
    </EntityLayout.Route>
    <EntityLayout.Route path="/feedback" title="Feedback">
      <EntityFeedbackResponseContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

const resourcePage = (
  <EntityLayoutWrapper>
    <EntityLayout.Route path="/" title="Overview">
      <Grid container spacing={3} alignItems="stretch">
        {entityWarningContent}
        <Grid item md={6}>
          <EntityAboutCard variant="gridItem" />
        </Grid>
        <Grid item md={6} xs={12}>
          <EntityCatalogGraphCard variant="gridItem" height={400} />
        </Grid>
        <Grid item md={6}>
          <EntityHasSystemsCard variant="gridItem" />
        </Grid>
      </Grid>
    </EntityLayout.Route>
    <EntityLayout.Route
      path="/kubernetes-cluster"
      title="Kubernetes Cluster"
      if={isKubernetesClusterAvailable}
    >
      <EntityKubernetesClusterContent />
    </EntityLayout.Route>
    <EntityLayout.Route
      path="/puppetdb"
      title="Puppet"
      if={isPuppetDbAvailable}
    >
      <PuppetDbPage />
    </EntityLayout.Route>
    <EntityLayout.Route path="/todos" title="TODOs">
      <EntityTodoContent />
    </EntityLayout.Route>
  </EntityLayoutWrapper>
);

export const entityPage = (
  <EntitySwitch>
    <EntitySwitch.Case if={isKind('component')} children={componentPage} />
    <EntitySwitch.Case if={isKind('api')} children={apiPage} />
    <EntitySwitch.Case if={isKind('group')} children={groupPage} />
    <EntitySwitch.Case if={isKind('user')} children={userPage} />
    <EntitySwitch.Case if={isKind('system')} children={systemPage} />
    <EntitySwitch.Case if={isKind('domain')} children={domainPage} />
    <EntitySwitch.Case if={isKind('resource')} children={resourcePage} />

    <EntitySwitch.Case>{defaultEntityPage}</EntitySwitch.Case>
  </EntitySwitch>
);
